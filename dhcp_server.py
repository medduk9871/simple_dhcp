import json
import logging
import socket

from OpenSSL import crypto

logger = logging.getLogger(__name__)

MAX_BYTES = 1024

serverPort = 67
clientPort = 68


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
                auth_opts_domain = self.create_dhcp_option('domain')
                auth_opts = auth_opts_root + auth_opts_domain
                sign = self.sign_data(data)
                for auth_opt in auth_opts:
                    s.sendto(data + sign + auth_opt, dest)

                while 1:
                    try:
                        print("Wait DHCP request.")
                        data, address = s.recvfrom(MAX_BYTES)
                        print("Receive DHCP request.")
                        # print(data)

                        print("Send DHCP pack.\n")
                        data = DHCP_server.pack_get()
                        s.sendto(data, dest)
                        break
                    except:
                        raise
            except:
                raise

    def offer_get():

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])  # 192.168.1.100
        SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 2])  # DHCP Offer
        DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server
        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5
        return package

    def create_dhcp_option(self, type):
        cert_types = {
            'domain': 1,
            'rootCA': 0
        }
        with open(f'keys/{type}.crt', 'r') as f:
            cert = f.read()
            total_length, split_length = len(cert), (400)
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
            sign = crypto.sign(pkey, data, "sha256")
            print(sign)
            return sign

    def pack_get():
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])
        SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 5])  # DHCP ACK(value = 5)
        DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

        return package


if __name__ == '__main__':
    dhcp_server = DHCP_server()
    dhcp_server.server()
