#!/usr/bin/env python2
# author: takeshix@adversec.com
import ssl, socket
from sstp import *

HTTP_REQ = """SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1
Host: vpn1.contoso.com
SSTPCORRELATIONID: {1}
Content-Length: 18446744073709551615

"""

def http_negotiation(s):
    s.write(HTTP_REQ)
    r = s.read()
    return r

def get_ssl_socket():
    HOST = 'vpn1.contoso.com'
    PORT = 443
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(s)
    ssl_sock.connect((HOST, PORT))
    return ssl_sock

def build_sstp_request():
    return SSTP()/SSTP_CONTROL_PACKET()/SSTP_MSG_CALL_CONNECT_REQUEST(attribute_id=0x01)

if __name__ == '__main__':
    try:
        s = get_ssl_socket()
        r = http_negotiation(s)
        if not 'HTTP/1.1 200' in r:
            raise Exception('SSTP negotiation failed')

        s.send(build_sstp_request().build())
        ret = s.recv(4096)
        sstp_response = SSTP(ret)

        print '[RAW] {}'.format(ret.encode('hex'))
        print sstp_response.show2()
    except Exception as e:
        print e
