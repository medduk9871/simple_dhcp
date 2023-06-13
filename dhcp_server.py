import json
import logging
import socket
import sys

from OpenSSL import crypto

from common import MAX_BYTES, serverPort, clientPort, CERT_SPLIT_LENGTH, SIGNATURE_LENGTH, cert_types, DHCPMessage, Option90

logger = logging.getLogger(__name__)

server_name = sys.argv[1]

class DHCP_server(object):

    def server(self):
        print("DHCP server is starting...\n")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(('', serverPort))
        dest = ('255.255.255.255', clientPort)

        while 1:
            try:
                print("Wait DHCP discovery.")
                data, address = s.recvfrom(MAX_BYTES)
                print("Receive DHCP discovery.")
                # print(data)

                print("Send DHCP offer.")
                data = DHCP_server.offer_get()
                auth_opts_root = self.create_dhcp_option('rootCA')
                auth_opts_domain = self.create_dhcp_option(server_name)
                auth_opts = auth_opts_root + auth_opts_domain
                sign = self.sign_data(data)
                for auth_opt in auth_opts:
                    opt = DHCPMessage.change_to_bytes(Option90.get_option_no(), 1) + DHCPMessage.change_to_bytes(len(sign + auth_opt), Option90._n_bytes_for_option_len)
                    new_data = DHCPMessage.add_option(data, opt + sign + auth_opt)
                    s.sendto(new_data, dest)

                while 1:
                    try:
                        print("Wait DHCP request.")
                        data, address = s.recvfrom(MAX_BYTES)
                        print("Receive DHCP request.")
                        # print(data)

                        print("Send DHCP pack.\n")
                        data = DHCP_server.pack_get()
                        sign = self.sign_data(data)
                        for auth_opt in auth_opts:
                            opt = DHCPMessage.change_to_bytes(Option90.get_option_no(), 1) + DHCPMessage.change_to_bytes(len(sign + auth_opt),
                                                                                                                         Option90._n_bytes_for_option_len)
                            new_data = DHCPMessage.add_option(data, opt + sign + auth_opt)
                            s.sendto(new_data, dest)
                        # s.sendto(data, dest)
                        break
                    except:
                        raise
            except:
                raise

    def offer_get():
        package = DHCPMessage.make_bytes(dict(OP=[0x02]
                                              , HTYPE=[0x01]
                                              , HLEN=[0x06]
                                              , HOPS=[0x00]
                                              , XID=[0x39, 0x03, 0xF3, 0x26]
                                              , SECS=[0x00, 0x00]
                                              , FLAGS=[0x00, 0x00]
                                              , CIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , YIADDR=[0xC0, 0xA8, 0x01, 0x64]  # 192.168.1.100
                                              , SIADDR=[0xC0, 0xA8, 0x01, 0x01]  # 192.168.1.1
                                              , GIADDR=[0x00, 0x00, 0x00, 0x00]
                                              , CHADDR=[0x00, 0x05, 0x3C, 0x04]
                                                       + [0x8D, 0x59, 0x00, 0x00]
                                                       + [0x00, 0x00, 0x00, 0x00]
                                                       + [0x00, 0x00, 0x00, 0x00]
                                              , MAGIC_COOKIE=[0x63, 0x82, 0x53, 0x63]))
        package = DHCPMessage.add_option(package, [53, 1, 2])  # DHCP Offer
        package = DHCPMessage.add_option(package, [1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        package = DHCPMessage.add_option(package, [3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        package = DHCPMessage.add_option(package, [51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        package = DHCPMessage.add_option(package, [54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server
        return package

    def create_dhcp_option(self, type):
        with open(f'keys/{type}.crt', 'r') as f:
            cert = f.read()
            total_length, split_length = len(cert), CERT_SPLIT_LENGTH
            split_certs = [cert[i:i + split_length] for i in range(0, total_length, split_length)]

            auth_opts = []
            for idx, split_cert in enumerate(split_certs):
                auth_opt = {
                    'type': cert_types[type],
                    'total_number': len(split_certs),
                    'cur_number': idx + 1,
                    'cert_length': len(cert),
                    'cert': split_cert,
                }
                body = json.dumps(auth_opt)
                body = bytes(body, 'utf-8')
                message = body
                auth_opts.append(message)
        return auth_opts

    def sign_data(self, data):
        with open(f'keys/domain.key', 'r') as f:
            private_key = f.read()
            password = bytes('abcd', 'utf-8')
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key, password)
            sign = crypto.sign(pkey, data, f"sha{SIGNATURE_LENGTH}")
            return sign

    def pack_get():
        package = DHCPMessage.make_bytes(
            dict(OP=[0x02]
                 , HTYPE=[0x01]
                 , HLEN=[0x06]
                 , HOPS=[0x00]
                 , XID=[0x39, 0x03, 0xF3, 0x26]
                 , SECS=[0x00, 0x00]
                 , FLAGS=[0x00, 0x00]
                 , CIADDR=[0x00, 0x00, 0x00, 0x00]
                 , YIADDR=[0xC0, 0xA8, 0x01, 0x64]
                 , SIADDR=[0xC0, 0xA8, 0x01, 0x01]
                 , GIADDR=[0x00, 0x00, 0x00, 0x00]
                 , CHADDR=[0x00, 0x05, 0x3C, 0x04]
                          + [0x8D, 0x59, 0x00, 0x00]
                          + [0x00, 0x00, 0x00, 0x00]
                          + [0x00, 0x00, 0x00, 0x00]
                 , MAGIC_COOKIE=[0x63, 0x82, 0x53, 0x63]))
        package = DHCPMessage.add_option(package, [53, 1, 5])  # DHCP ACK(value = 5
        package = DHCPMessage.add_option(package, [1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        package = DHCPMessage.add_option(package, [3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        package = DHCPMessage.add_option(package, [51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day IP address lease time
        package = DHCPMessage.add_option(package, [54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

        return package


if __name__ == '__main__':
    if server_name != "domain" and server_name != "rogue":
        exit('invalid server name')

    dhcp_server = DHCP_server()
    dhcp_server.server()
