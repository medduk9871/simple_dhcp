import json
import socket
import sys

from OpenSSL import crypto

from cert_verify import verify_certificate_chain

MAX_BYTES = 1024

serverPort = 67
clientPort = 68

cert_types = {
    1: 'domain',
    0: 'rootCA'
}
from enum import Enum


class DHCPauthType(Enum):
    CA = 0
    SERVER = 1


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

        data, address = self.check_cert_verify_and_get_data(s)
        print("Receive DHCP pack.\n")
        # print(data)

    def get_cert(self, rootCA_auth_opts):
        rootCA_cert = ""
        for key in rootCA_auth_opts:
            cur_auth_opt = rootCA_auth_opts[key]
            rootCA_cert += cur_auth_opt
        return rootCA_cert

    def receive_offer(self, s):
        rootCA_auth_opts = {}
        data, address = s.recvfrom(MAX_BYTES)
        origin_msg, auth_opt, signature = self.get_auth_opt(data)
        print(
            f"Receive DHCP offer with auth option ({cert_types[auth_opt['type']]} {auth_opt['cur_number']}/{auth_opt['total_number']})")
        rootCA_auth_opts[auth_opt['cur_number']] = auth_opt['cert']
        for idx in range(auth_opt['total_number'] - 1):
            data, address = s.recvfrom(MAX_BYTES)
            origin_msg, auth_opt, signature = self.get_auth_opt(data)
            rootCA_auth_opts[auth_opt['cur_number']] = auth_opt['cert']
            print(
                f"Receive DHCP offer with auth option ({cert_types[auth_opt['type']]} {auth_opt['cur_number']}/{auth_opt['total_number']})")
        rootCA_auth_opts = dict(sorted(rootCA_auth_opts.items()))
        return origin_msg, address, rootCA_auth_opts, signature

    def check_cert_verify_and_get_data(self, s):
        """
        :param s: socket to recieve data
        :return: the recieved data
        """
        cert_dict = {}
        data, address, rootCA_auth_opts, signature = self.receive_offer(s)
        rootCA_cert = self.get_cert(rootCA_auth_opts)
        cert_dict[DHCPauthType.CA] = rootCA_cert
        data, address, domain_auth_opts, signature = self.receive_offer(s)
        domain_cert = self.get_cert(domain_auth_opts)
        cert_dict[DHCPauthType.SERVER] = domain_cert

        print(cert_dict)

        print("Checking cert validity...")

        if not verify_certificate_chain(cert_dict[DHCPauthType.SERVER], [cert_dict[DHCPauthType.CA]]):
            print("Cert invalid!")
            sys.exit(1)

        crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_dict[DHCPauthType.SERVER])
        if not crypto.verify(crtObj, signature, data, 'sha256'):
            print("Signature invalid!")
            sys.exit(1)

        return data, address

    def get_auth_opt(self, data):
        origin_msg = data[:267]
        sign = data[267: 267 + 256]
        auth_opt = data[267 + 256:]
        auth_opt_body = auth_opt
        # json to dict
        di = eval(str(auth_opt_body))
        return origin_msg, json.loads(di.decode('utf-8')), sign

    def discover_get():
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 1])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2

        return package

    def request_get():
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x0C, 0x29, 0xDD])
        CHADDR2 = bytes([0x5C, 0xA7, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 3])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])
        DHCPOptions3 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3

        return package


if __name__ == '__main__':
    dhcp_client = DHCP_client()
    dhcp_client.client()
