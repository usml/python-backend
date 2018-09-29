import re

from ctypes import *
from functools import reduce

__author__ = 'Alexander V. Ignatyev <ignatev@intersvyaz.net>'

VENDORS = {
    3302: "BDCOM",
}

re_cidr = re.compile(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:/(\d+))?$')
re_hwaddr = re.compile(r'^([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2}):([0-9a-f]{2})$', re.I)


class NumericList(object):
    length = None

    def __init__(self, value):
        if self.length and len(value) != self.length:
            raise ValueError("Invalid length")

        self._size = len(value)
        _struct = c_uint8 * len(value)

        if isinstance(value, (str, bytes)):
            self._value = _struct.from_buffer_copy(value)
        else:
            self._value = _struct(*value)

    @property
    def packed(self):
        return string_at(self._value, self._size)

    @property
    def bytes(self):
        return self._value[:]

    def __len__(self):
        return self._size

    def __hash__(self):
        return string_at(self._value, self._size)

    def __str__(self):
        return string_at(self._value, self._size)

    def __iter__(self):
        for b in self._value[:]:
            yield b

    def __reduce__(self):
        # make object serializeable by pickle
        return (self.__class__, (self.bytes,))


class UINT(NumericList):
    def __init__(self, value):
        if self.length and isinstance(value, int):
            buff = []
            while value:
                buff.insert(0, value & 255)
                value >>= 8

            buff = [0] * (self.length - len(buff)) + buff
            super(UINT, self).__init__(buff)
        else:
            super(UINT, self).__init__(value)

    def __hash__(self):
        return int(self)

    def __cmp__(self, other):
        return cmp(int(self), int(other))

    def __nonzero__(self):
        return int(self) != 0

    def __index__(self):
        return int(self)

    def __int__(self):
        value = 0
        for byte in self._value[:]:
            value <<= 8
            value += byte

        return value


class UINT8(UINT):
    length = 1


class UINT16(UINT):
    length = 2


class UINT32(UINT):
    length = 4


class IPv4(UINT32):
    @classmethod
    def from_cidr(cls, value):
        cidr = re_cidr.match(value)

        if not cidr:
            raise ValueError("Invalid CIDR string")

        return cls([int(cidr.group(group + 1)) for group in xrange(4)])

    def __str__(self):
        return '.'.join(['%d' % b for b in self._value[:]])

    def __repr__(self):
        return str(self)


class IPNetworkv4(UINT32):
    def __init__(self, network_addr, prefix_len=32):
        super(IPNetworkv4, self).__init__(network_addr)

        self.prefix_len = prefix_len
        self.network_mask = (0xffffffff << 32 - prefix_len) & 0xffffffff
        self.network_addr = IPv4(int(self) & self.network_mask)

    @classmethod
    def from_cidr(cls, value):
        cidr = re_cidr.match(value)

        if not cidr:
            raise ValueError("Invalid CIDR string")

        return cls(network_addr=[int(cidr.group(group + 1)) for group in xrange(4)], prefix_len=int(cidr.group(5)))

    def __str__(self):
        return '.'.join(['%d' % b for b in self._value[:]]) + '/%d' % self.prefix_len

    def __repr__(self):
        return str(self)

    def __contains__(self, item):
        return int(item) & self.network_mask == self.network_addr


class HWADDR(UINT):
    length = 6

    @classmethod
    def from_string(cls, value):
        hwaddr = re_hwaddr.match(value)

        if not hwaddr:
            raise ValueError("Invalid HWADDR string")

        return cls(map(lambda h: int(h, 16), hwaddr.groups()))

    def __str__(self):
        return ':'.join(['%02x' % b for b in self._value[:]])

    def __repr__(self):
        return str(self)


class TLVHeader(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('tag', c_uint8),
        ('length', c_uint8)
    ]

    # TODO: test which one os faster
    header_len = reduce(lambda bytes, field: bytes + sizeof(field[1]), _fields_, 0)


class DLinkCircuitID(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('vlan', c_uint16),
        ('module', c_uint8),
        ('port', c_uint8)
    ]

class SNRCircuitID(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('vlan', c_uint16),
        ('module', c_uint8),
        ('stack', c_uint8),
        ('port', c_uint16)
    ]

class BDCOMCircuitID(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('vlan', c_uint16),
        ('module', c_uint8),
        ('port', c_uint8),
        ('llid', c_uint8),
    ]


def parse_tlv(buff):
    """ Decode buffer as sequence of TLV encoded items

    :param buff:  sequence of TLV encoded items
    :type buff: str
    :return: generator (returns item tag, item value while iterating)
    """
    offset = 0

    while offset < len(buff):
        # read item header
        header = TLVHeader.from_buffer_copy(buff, offset)

        # set seek position just after the TLV header
        offset += header.header_len

        # ensure if we can read specified bytes from buffer
        if offset + header.length > len(buff):
            raise ValueError('Invalid TLV encoded item: header_tag=%s, header_len=%s' % (header.tag, header.length))

        # read item value from buffer
        tag_data = buff[offset:offset + header.length]

        # calculate offset for next item
        offset += header.length

        # yield item
        yield header.tag, tag_data


class O82AgentCircuitID(object):
    def __init__(self, data):
        self.bytes = data

        if data[:4] == 'GPON':
            # GPON Eltex v2
            self.attrs = [(256, data)]
        elif data[:6] == chr(1) + chr(12) + 'DSNW':
            # GPON Dasan
            self.attrs = [(257, data)]
        elif data[:15] == 'FORMAT=ELTX-V3,':
            # GPON Eltex v3
            self.attrs = [(258, data)]
        elif len(data) == 5:
            self.attrs = [(259, data)]
        else:
            self.attrs = list(parse_tlv(data))

    @property
    def get(self):
        attr_type, attr_value = self.attrs[0]

        if attr_type == 0 and len(attr_value) == 4:
            # D-Link circuit ID format
            circuit_id = DLinkCircuitID.from_buffer_copy(attr_value)

            return circuit_id.vlan, circuit_id.module, circuit_id.port
        elif attr_type == 0 and len(attr_value) == 6:
            # D-Link circuit ID format
            circuit_id = SNRCircuitID.from_buffer_copy(attr_value)

            return circuit_id.vlan, circuit_id.module, circuit_id.port
        elif attr_type == 256:
            gpon_flag = attr_value[:4]
            vlan = int((attr_value[4] + attr_value[5]).encode('hex'), 16)
            ont_serial = attr_value[6:10] + attr_value[10:].encode('hex')
            return vlan, 0, ont_serial
        elif attr_type == 257:
            ont_serial = attr_value[2:]
            return 0, 0, ont_serial
        elif attr_type == 258:
            ont_serial = ''

            # key-value pairs are divided by ","
            key_values = attr_value.split(',')
            for key_value in key_values:
                key, value = key_value.split('=')
                if key == 'ONT':
                    ont_serial = value

            return 0, 0, ont_serial
        elif attr_type == 259:
            # D-Link circuit ID format
            circuit_id = BDCOMCircuitID.from_buffer_copy(attr_value)
            return circuit_id.vlan, circuit_id.port, circuit_id.llid

        return None

    def __str__(self):
        return str(self.get)


class O82AgentRemoteID(object):
    def __init__(self, data):
        self.bytes = data
        if data[:4] == 'gpon':
            self.attrs = [(255, data)]
        elif len(data) == 6:
            self.attrs = [(0, data)]
        else:
            self.attrs = list(parse_tlv(data))

    @property
    def get(self):
        attr_type, attr_value = self.attrs[0]

        if attr_type == 0 and len(attr_value) == 6:
            return ':'.join(['%02x' % ord(i) for i in attr_value])
        elif attr_type == 1:
            if len(attr_value) == 17:
                remote_id = [i for i in attr_value if ord(i) != 45]
                remote_id = [int(''.join(pair), 16) for pair in zip(remote_id[::2], remote_id[1::2])]

                return ':'.join(['%02x' % i for i in remote_id])
            else:
                return attr_value
        elif attr_type == 255:
            return attr_value

        return None

    def __str__(self):
        return self.get


class O82VendorSpecific(object):
    def __init__(self, data, vendor=None):
        self.bytes = data
        self.enterprise_num = None
        self.data = {}

    @property
    def get(self):
        enterprise_id, enterprise_data = self.bytes[:4], self.bytes[4:]
        self.enterprise_num = UINT32(enterprise_id)

        data_len, data_raw = enterprise_data[0], enterprise_data[1:]
        for data_code, data_value in parse_tlv(data_raw):
            self.data[data_code] = data_value

        return self.enterprise_num, self.data

    def __str__(self):
        return self.get


class Option82(object):
    """
    The Relay Agent Information Option protocol extension (RFC 3046, usually referred to in the industry by its
    actual number as Option 82) allows network operators to attach tags to DHCP messages as these messages
    arrive on the network operator's trusted network. This tag is then often used as an authorization token to
    control the client's access to network resources.
    """

    SUBOPTION_CODE = {
        'agent_circuit_id': 1,
        'agent_remote_id': 2,
        'vendor_specific': 9,
    }

    #_suboption_code = {
    #    'agent_circuit_id': 1,
    #    'agent_remote_id': 2,
    #    'vendor_specific': 9,
    #}

    _suboption_decoder = {
        1: O82AgentCircuitID,
        2: O82AgentRemoteID,
        9: O82VendorSpecific,
    }

    def __init__(self, data):
        """
        Constructor.

        :param data: DHCP option 82 field value as byte array

        """

        self.suboptions = dict(parse_tlv(data))
        self.vendor = None

        self._vendor_data = {}
        self._suboptions_decoded = {}

        # decode specific suboptions first
        # generic suboptions decoders can be vendor specific
        if self.SUBOPTION_CODE['vendor_specific'] in self.suboptions:
            suboption_vendor_specific = self.decode(self.SUBOPTION_CODE['vendor_specific'])

            _vendor_id, self._vendor_data = suboption_vendor_specific
            self.vendor = int(_vendor_id)

    @property
    def encode(self):
        data = ''

        for suboption_code, suboption in self.suboptions.iteritems():
            data += chr(suboption_code) + chr(len(suboption)) + suboption

        return data

    def decode(self, suboption):
        """Decodes suboption from byte vector to something usefull

        Each suboption has it's own format as described in related RFCs.
        But it is not mandatory, so we can't expect strict RFC compilance.

        Args:
            suboption: Unique suboption code as integer

        Returns:
            None or decoded value for suboption. Returned data format defined by
            used decoder.

        Raises:
            Exception: Non-callable decoder for option
        """
        if suboption not in self.suboptions:
            return None

        # decoder should be defined for specified suboption
        decoder = self._suboption_decoder.get(suboption)
        if not callable(decoder):
            raise Exception("Undecodable suboption: %s" % suboption)

        self._suboptions_decoded[suboption] = decoder(self.suboptions[suboption]).get
        return self._suboptions_decoded[suboption]

    def __bdcom_remote_id(self):
        if len(self._vendor_data) == 1 and 1 in self._vendor_data:
            return self._vendor_data[1]
        elif len(self._vendor_data) == 3 and 2 in self._vendor_data:
            return self._vendor_data[2]

        return None

    def __bdcom_circuit_id(self):
        onu_mac = self.decode(2)
        vlan, pon_port, llid = self.decode(1)

        return pon_port, llid, onu_mac

    def __getitem__(self, suboption):
        # validate givaen suboption
        # strings and integers are or, otherwise None will be returned
        if isinstance(suboption, (str, bytes)):
            if suboption not in self.SUBOPTION_CODE:
                return None

            suboption = self.SUBOPTION_CODE[suboption]

        if suboption not in self.suboptions:
            return None

        if self.vendor == 3320 and suboption == 1:
            return self.__bdcom_circuit_id()
        elif self.vendor == 3320 and suboption == 2:
            return self.__bdcom_remote_id()

        return self._suboptions_decoded.get(suboption, None) or self.decode(suboption)


class Option121_old:
    def __init__(self, routes):
        self._routes = []
        for subnet, gw in routes.iteritems():
            network = IPNetworkv4.from_cidr(subnet)
            gateway = IPv4.from_cidr(gw)

            self._routes.append((network.network_addr, network.prefix_len, network.network_addr.bytes, gateway.bytes))

    def ListClasslessRoutes(self):
        result = []

        for route in self._routes:
            result.append(route[1])
            for i in xrange(4):
                if route[1] > i * 8:
                    result.append(route[2][i])

            result.extend(route[3])

        return result

class Option121:
    def __init__(self, routes):
        self._routes = []
        for subnet, gw in routes.iteritems():
            self._routes.append((IPNetworkv4.from_cidr(subnet), IPv4.from_cidr(gw)))

    @property
    def packed(self):
        return str(self)

    def __repr__(self):
        return "%s(%r)" % (self.__class__, self._routes)

    def __str__(self):
        result = ''

        for subnet, gw in self._routes:
            result += chr(subnet.prefix_len)

            octets = 0
            if subnet.prefix_len > 0:
                octets = ((subnet.prefix_len - 1) // 8) + 1

            result += subnet.packed[:octets] + gw.packed

        return result
