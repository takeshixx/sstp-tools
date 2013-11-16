from scapy.packet import *
from scapy.fields import *

class SSTPLenField(BitField):
    def __init__(self,name,default,size):
        BitField.__init__(self,name,default,size)

    def i2m(self,pkt,x):
        if x is None:
            return len(pkt.__dict__['payload']) + 4
        return x

class SSTPInnerLenField(BitField):
    def __init__(self,name,default,size):
        BitField.__init__(self,name,default,size)

    def i2m(self,pkt,x):
        if x is None:
            return len(pkt.__dict__['payload']) + 12
        return x


_SSTP_packet_types = {
    0x00:'Data Packet',
    0x01:'Control Packet'
}

class SSTP(Packet):
    name = 'Secure Socket Tunneling Protocol'
    
    fields_desc = [
        XByteField('version',0x10),
        BitField('reserved',0,7),
        BitEnumField('packet_type',None,1,_SSTP_packet_types),
        BitField('reserved_len',0,4),
        SSTPLenField('lengthpacket',None,12)
    ]

class SSTP_DATA_PACKET(Packet):
    name = 'SSTP Data Packet'

    fields_desc = [
        ByteField('payload',None) 
    ]

_SSTP_control_message_types = {
    0x0001:'SSTP_MSG_CALL_CONNECT_REQUEST',
    0x0002:'SSTP_MSG_CALL_CONNECT_ACK',
    0x0003:'SSTP_MSG_CALL_CONNECT_NAK',
    0x0004:'SSTP_MSG_CALL_CONNECTED',
    0x0005:'SSTP_MSG_CALL_ABORT',
    0x0006:'SSTP_MSG_CALL_DISCONNECT',
    0x0007:'SSTP_MSG_CALL_DISCONNECT_ACK',
    0x0008:'SSTP_MSG_ECHO_REQUEST',
    0x0009:'SSTP_MSG_ECHO_RESPONSE'
}

_SSTP_attribute_ids = {
    0x01:'SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID',
    0x02:'SSTP_ATTRIB_STATUS_INFO',
    0x03:'SSTP_ATTRIB_CRYPTO_BINDING',
    0x04:'SSTP_ATTRIB_CRYPTO_BINDING_REQ'
}

class SSTP_CONTROL_PACKET(Packet):
    name = 'SSTP Control Packet'

    fields_desc = [
        ShortEnumField('message_type',None,_SSTP_control_message_types),
        ShortField('num_attributes',0x0001)
    ]

class SSTP_ATTRIBUTE(Packet):
    name = 'SSTP Attribute'

    fields_desc = [
        ByteField('reserved1',0x00),
        ByteEnumField('attribute_id',None,_SSTP_attribute_ids),
        BitField('reserved_len1',0,4),
        SSTPLenField('lengthpacket1',None,12)
    ]
        
class SSTP_MSG_CALL_CONNECT_REQUEST(Packet):
    name = 'SSTP Call Connect Request Message'

    fields_desc = [
        ByteField('reserved1',0x00),
        ByteEnumField('attribute_id',None,_SSTP_attribute_ids),
        BitField('reserved_len1',0,4),
        BitField('lengthpacket1',0x006,12),
        XShortField('protocol_id',0x0001)
    ]

class SSTP_MSG_CALL_CONNECT_ACK(Packet):
    name = 'SSTP Call Connect Acknowledgment Message'
    
    fields_desc = [
        XByteField('reserved1',0x00),
        ByteEnumField('attribute_id',0x04,_SSTP_attribute_ids),
        BitField('reserved_len1',0,4),
        BitField('lengthpacket1',0x028,12),
        BitField('reserved2',0x00,24),
        XByteField('hash_protocol_bitmask',0x02),
        BitField('nonce',0x00,256)
    ]

_SSTP_abort_status = {
    0x00000001:'ATTRIB_STATUS_DUPLICATE_ATTRIBUTE',
    0x00000002:'ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE',
    0x00000003:'ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH',
    0x00000004:'ATTRIB_STATUS_VALUE_NOT_SUPPORTED',
    0x00000005:'ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED',
    0x00000006:'ATTRIB_STATUS_RETRY_COUNT_EXCEEDED',
    0x00000007:'ATTRIB_STATUS_INVALID_FRAME_RECEIVED',
    0x00000008:'ATTRIB_STATUS_NEGOTIATION_TIMEOUT',
    0x00000009:'ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG',
    0x0000000A:'ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING',
    0x0000000B:'ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG'
}

class SSTP_MSG_CALL_CONNECT_NAK(Packet):
    name = 'SSTP Call Connect Negative Acknowledgment Message' 

    fields_desc = [
        XByteField('reserved1',0x00),
        ByteEnumField('attribute_id',0x02,_SSTP_attribute_ids),
        BitField('reserved_len1',0,4),
        SSTPInnerLenField('lengthpacket1',None,12),
        BitField('reserved2',0x00,24),
        ByteEnumField('attribid',None,_SSTP_attribute_ids),
        BitEnumField('status',None,32,_SSTP_abort_status),
        # max 64 byte attribvalue, tbd
    ]

class SSTP_MSG_CALL_ABORT(Packet):
    name = 'SSTP CALL ABORT Message'

    fields_desc = [
        ByteField('reserved1',0),
        ByteEnumField('attribute_id',0,_SSTP_attribute_ids),
        ShortField('length',0x14),
        X3BytesField('reserved2',0),
        XByteField('attribid',0),
        BitEnumField('status',None,32,_SSTP_abort_status),
    ]

class SSTP_MSG_CALL_CONNECTED(Packet):
    name = 'Call Connected Message'

    fields_desc = [
        ByteField('reserved1',0),
        ByteEnumField('attribute_id',0,_SSTP_attribute_ids),
        BitField('reserved_len1',0,4),
        SSTPInnerLenField('lengthpacket1',None,12),
        X3BytesField('reserved2',0),
        ByteField('hash_protocol_bitmask',0x02),
        XBitField('none',None,256),
        XBitField('client_hash',None,160), # SHA1:160,SHA256:256
        BitField('padding',0x00,96), # SHA1:96,SHA256:0 
        XBitField('compound_mac',None,160), # SHA1:160,SHA256:256
        BitField('padding1',0x00,96), # SHA1:96,SHA256:0 
    ]

class SSTP_MSG_CALL_DISCONNECT(Packet):
    name = 'Call Disconnect Message'

    fields_desc = [
        ByteField('reserved1',0),
        ByteEnumField('attribute_id',0,_SSTP_attribute_ids),
        BitField('reserved_len1',0,4),
        SSTPInnerLenField('lengthpacket1',None,12),
        X3BytesField('reserved2',0),
        ByteField('attreibid',0x00),
        BitField('status',0x00,32)
    ]

class SSTP_MSG_CALL_DISCONNECT_ACK(Packet):
    name = 'Call Disconnect Acknowledgment Message'

class SSTP_MSG_ECHO_REQUEST(Packet):
    name = 'Echo Request Message'

class SSTP_MSG_ECHO_RESPONSE(Packet):
    name = 'Echo Response Message'

bind_layers(SSTP, SSTP_DATA_PACKET, packet_type=0x00)
bind_layers(SSTP, SSTP_CONTROL_PACKET, packet_type=0x01)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_CONNECT_REQUEST, message_type=0x0001)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_CONNECT_ACK, message_type=0x0002)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_CONNECT_NAK, message_type=0x0003)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_CONNECTED, message_type=0x0004)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_ABORT, message_type=0x0005)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_DISCONNECT, message_type=0x0006)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_CALL_DISCONNECT_ACK, message_type=0x0007)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_ECHO_REQUEST, message_type=0x0008)
bind_layers(SSTP_CONTROL_PACKET, SSTP_MSG_ECHO_RESPONSE, message_type=0x0009)
