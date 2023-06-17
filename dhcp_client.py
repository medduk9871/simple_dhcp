import socket
import sys

from OpenSSL import crypto

from cert_verify import verify_certificate_chain
from common import MAX_BYTES, serverPort, clientPort, SIGNATURE_LENGTH, cert_types, DHCPMessage, Option90, Option51


class DHCP_client(object):
    def client(self):
        print("DHCP client is starting...\n")
        dest = ('<broadcast>', serverPort)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(('0.0.0.0', clientPort))

        print("Send DHCP discovery.")
        data = DHCP_client.discover_get()
        s.sendto(data, dest)

        data, address = self.check_cert_verify_and_get_data(s)

        print("Send DHCP request.")
        data = DHCP_client.request_get()
        s.sendto(data, dest)

        data, address = self.check_sign_and_get_ack(s)
        print("Receive DHCP pack.\n")
        got_ip = data['YIADDR']
        expire_days = data[Option51.get_option_no()]
        print(f"Recieved IP: {got_ip}. It will expire in {expire_days} days.")

    def get_cert(self, issuerCA_auth_opts):
        issuerCA_cert = ""
        for key in issuerCA_auth_opts:
            cur_auth_opt = issuerCA_auth_opts[key]
            issuerCA_cert += cur_auth_opt
        return issuerCA_cert

    def receive_ack(self, s):
        data, address = s.recvfrom(MAX_BYTES)
        signed_raw, full_data_dict = self.get_auth_opt(data)
        signature = full_data_dict[Option90.get_option_no()]
        return signed_raw, address, full_data_dict, signature

    def receive_offer(self, s):
        auth_opts = {}
        data, address = s.recvfrom(MAX_BYTES)
        signed_raw, full_data_dict = self.get_auth_opt(data)
        auth_opt = full_data_dict[Option90.get_option_no()]
        print(
            f"Receive DHCP offer with auth option ({cert_types[auth_opt['type']]} {auth_opt['cur_number']}/{auth_opt['total_number']})")
        auth_opts[auth_opt['cur_number']] = auth_opt['cert']
        for idx in range(auth_opt['total_number'] - 1):
            data, address = s.recvfrom(MAX_BYTES)
            signed_raw, full_data_dict = self.get_auth_opt(data)
            auth_opt = full_data_dict[Option90.get_option_no()]
            auth_opts[auth_opt['cur_number']] = auth_opt['cert']
            print(
                f"Receive DHCP offer with auth option ({cert_types[auth_opt['type']]} {auth_opt['cur_number']}/{auth_opt['total_number']})")
        auth_opts = dict(sorted(auth_opts.items()))
        cert = self.get_cert(auth_opts)
        return signed_raw, address, full_data_dict, cert

    def check_sign_and_get_ack(self, s):
        """
        :param s: socket to recieve data
        :return: the recieved data
        """
        signed_raw, address, full_data_dict, signature = self.receive_ack(s)

        print("Checking signature validity...")
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert_dict[cert_types['domain']])
        try:
            crypto.verify(crtObj, signature, signed_raw, f'sha{SIGNATURE_LENGTH}')
        except Exception as e:
            print("Signature invalid!")
            print(e)
            sys.exit(1)
        print("Signature Valid!")

        return full_data_dict, address

    def check_cert_verify_and_get_data(self, s):
        """
        :param s: socket to recieve data
        :return: the recieved data
        """
        self.cert_dict = {}
        signed_data, address, full_data_dict, cert = self.receive_offer(s)
        auth_opt = full_data_dict[Option90.get_option_no()]
        self.cert_dict[auth_opt['type']] = cert
        signed_data, address, full_data_dict, cert = self.receive_offer(s)
        auth_opt = full_data_dict[Option90.get_option_no()]
        self.cert_dict[auth_opt['type']] = cert

        print("Checking cert validity...")
        if not verify_certificate_chain(self.cert_dict[cert_types['domain']], [open("keys/rootCA.crt").read(), self.cert_dict[cert_types['issuerCA']]]):
            print("Cert invalid!")
            sys.exit(1)
        print("Cert Valid!")

        print("Checking signature validity...")
        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.cert_dict[cert_types['domain']])
        try:
            crypto.verify(crtObj, auth_opt['signature'], signed_data, f'sha{SIGNATURE_LENGTH}')
        except Exception as e:
            print("Signature invalid!")
            print(e)
            sys.exit(1)
        print("Signature Valid!")

        return full_data_dict, address

    def get_auth_opt(self, data):
        option_no = Option90.get_option_no()
        signed_raw_data, full_data_dict = list(DHCPMessage.parse(data, [option_no]))
        return signed_raw_data, full_data_dict

    def discover_get():
        package = DHCPMessage.make_bytes(dict(OP=[0x01]
                                              , HTYPE=[0x01]
                                              , HLEN=[0x06]
                                              , HOPS=[0x00]
                                              , XID=[0x39, 0x03, 0xF3, 0x26]
                                              , SECS=[0x00, 0x00]
                                              , FLAGS=[0x00, 0x00]
                                              , CIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , YIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , SIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , GIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , CHADDR=[0x00, 0x05, 0x3C, 0x04]
                                                       + [0x8D, 0x59, 0x00, 0x00]
                                                       + [0x00, 0x00, 0x00, 0x00]
                                                       + [0x00, 0x00, 0x00, 0x00]
                                              , MAGIC_COOKIE=[0x63, 0x82, 0x53, 0x63]))
        package = DHCPMessage.add_option(package, [53, 1, 1])
        package = DHCPMessage.add_option(package, [50, 4, 0xC0, 0xA8, 0x01, 0x64])

        return package

    def request_get():
        package = DHCPMessage.make_bytes(dict(OP=[0x01]
                                              , HTYPE=[0x01]
                                              , HLEN=[0x06]
                                              , HOPS=[0x00]
                                              , XID=[0x39, 0x03, 0xF3, 0x26]
                                              , SECS=[0x00, 0x00]
                                              , FLAGS=[0x00, 0x00]
                                              , CIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , YIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , SIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , GIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , CHADDR=[0x00, 0x0C, 0x29, 0xDD]
                                                       + [0x5C, 0xA7, 0x00, 0x00]
                                                       + [0x00, 0x00, 0x00, 0x00]
                                                       + [0x00, 0x00, 0x00, 0x00]
                                              , MAGIC_COOKIE=[0x63, 0x82, 0x53, 0x63]))
        package = DHCPMessage.add_option(package, [53, 1, 3])
        package = DHCPMessage.add_option(package, [50, 4, 0xC0, 0xA8, 0x01, 0x64])
        package = DHCPMessage.add_option(package, [54, 4, 0xC0, 0xA8, 0x01, 0x01])

        return package


if __name__ == '__main__':
    dhcp_client = DHCP_client()
    dhcp_client.client()
