import collections

MAX_BYTES = 1024
serverPort = 67
clientPort = 68
CERT_SPLIT_LENGTH = 400
SIGNATURE_LENGTH = 256 # must be 256 or 512, which have to be suffix for sha{SIGNATURE_LENGTH}

cert_types = {
    'domain': 1,
    'rootCA': 0,
    'rogue': 1,
    1: 'domain',
    0: 'rootCA'
}
from collections import defaultdict

def default_parse(data):
    return '.'.join([str(s) for s in list(data)])


class Option:
    options_dict = {}
    _n_bytes_for_option_len = 1
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.options_dict[cls.get_option_no()] = cls

    @classmethod
    def get_option_cls(cls, option_no):
        return cls.options_dict[option_no]

    @classmethod
    def n_bytes_for_option_len(cls, option_no):
        if option_no in cls.options_dict:
            return cls.get_option_cls(option_no)._n_bytes_for_option_len
        return cls._n_bytes_for_option_len

    @classmethod
    def get_option_no(cls):
        return int(cls.__name__[len('Option'):])

    @classmethod
    def parse(cls, option_no, data):
        if option_no in cls.options_dict:
            return cls.get_option_cls(option_no).parse(data)
        return default_parse(data)

class Option51(Option):
    @classmethod
    def parse(cls, data):
        return int.from_bytes(data, 'big')

class Option90(Option):
    _n_bytes_for_option_len = 2
    @classmethod
    def parse(cls, data):
        import json
        auth_opt = data[SIGNATURE_LENGTH:]
        sign = data[:SIGNATURE_LENGTH]
        # json to dict
        di = eval(str(auth_opt))
        auth_opt = json.loads(di.decode('utf-8'))
        auth_opt['signature'] = sign
        return auth_opt


class DHCPMessage:
    key_to_length = {
        'OP': 1,
        'HTYPE': 1,
        'HLEN': 1,
        'HOPS': 1,
        'XID': 4,
        'SECS': 2,
        'FLAGS': 2,
        'CIADDR': 4,
        'YIADDR': 4,
        'SIADDR': 4,
        'GIADDR': 4,
        'CHADDR': 16,
        'SNAME': 64,
        'FILE': 128,
        'MAGIC_COOKIE': 4,
    }

    @classmethod
    def parse(cls, orig_data, yield_orig_data_before_option_no=None):
        data_dict = {}
        data = orig_data
        total_len = 0
        for key, length in cls.key_to_length.items():
            data_dict[key] = default_parse(data[:length])
            total_len += length
            data = data[length:]
        while data:
            option_no = data[0]
            if option_no == yield_orig_data_before_option_no[0]:
                yield orig_data[:total_len]
                yield_orig_data_before_option_no.pop(0)
            len_bytes_len = Option.n_bytes_for_option_len(option_no)
            option_length = int.from_bytes(data[1:1+len_bytes_len], 'big')
            option_data = data[1+len_bytes_len:1+len_bytes_len+option_length]
            data_dict[option_no] = Option.parse(option_no, option_data)
            data = data[1+len_bytes_len+option_length:]
            total_len += 1+len_bytes_len+option_length

        yield data_dict

    @classmethod
    def make_bytes(cls, got_data_dict):
        assert set(got_data_dict.keys()) < set(cls.key_to_length.keys())
        data_dict = collections.defaultdict(int)
        data_dict.update(got_data_dict)
        data = b''
        for key, length in cls.key_to_length.items():
            data += cls.change_to_bytes(data_dict[key], length)

        return data

    @classmethod
    def change_to_bytes(cls, data, length=None):
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, int):
            data = data.to_bytes(length, 'big')
        elif isinstance(data, list):
            data = bytes(data)
        else:
            assert isinstance(data, bytes)
        return data

    @classmethod
    def add_option(cls, data, option):
        return data + cls.change_to_bytes(option)
