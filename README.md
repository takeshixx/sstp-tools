sstp-tools
==========

### SSTP Info
Current server implementations:
  * Microsoft Windows (Server 2008/Server 2012)
  * MikroTik RouterOS

Current client implementations:
  * Microsoft Windows (>Vista SP1 & Server 2008/Server 2012)
  * MikroTik RouterOS
  * sstp-client (http://sstp-client.sourceforge.net/)
  * SSToPer (https://github.com/hugsy/sstoper)

Further information:
  * http://msdn.microsoft.com/en-us/library/cc247338.aspx
  * http://support.microsoft.com/kb/947054

### Nmap Scripts

#### sstp-discover.nse
This script can be used to check if SSTP is supported on a given host (checks only port 443).

Sample output:
```
[ ~/temp ] nmap --script sstp-discover -p443 172.24.10.30   

Starting Nmap 6.41SVN ( http://nmap.org ) at 2013-11-02 01:35 CET
Nmap scan report for vpn1.contoso.com (172.24.10.30)
Host is up (0.0010s latency).
PORT    STATE SERVICE
443/tcp open  https
| sstp-discover: 
|   status: SSTP is supported!
|   server: Microsoft-HTTPAPI/2.0
|_  timestamp: Fri, 01 Nov 2013 09:45:01 GMT
```

### Scapy Templates

Scapy SSTP layer, currently implemented control messages:
  * SSTP_MSG_CALL_CONNECT_REQUEST
  * SSTP_MSG_CALL_CONNECT_ACK
  * SSTP_MSG_CALL_CONNECT_NAK
  * SSTP_MSG_CALL_ABORT

Not yet supported control messages:
  * SSTP_MSG_CALL_CONNECTED
  * SSTP_MSG_CALL_DISCONNECT
  * SSTP_MSG_CALL_DISCONNECT_ACK
  * SSTP_MSG_ECHO_REQUEST
  * SSTP_MSG_ECHO_RESPONSE

#### sstp-negotiation.py
This is a test script that executes three steps in order to establish the SSTP layer:
  * Creating of a SSL socket
  * HTTP layer negotiation
  * SSTP layer negotiation

Note: This code is highly experimental!
