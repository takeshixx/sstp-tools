sstp-tools
==========

This is a small collection of tools for the Secure Socket Tunneling Protocol. Most parts will be (and may stay) highly experimental.

Todo:
  * Scapy template (partially done)
  * Dizzy template (tbd)

### SSTP Info
Current server implementations:
  * Microsoft Windows (Server 2008/Server 2012)
  * MikroTik RouterOS (http://wiki.mikrotik.com/wiki/Manual:Interface/SSTP)
  * SoftEther VPN (https://github.com/SoftEtherVPN/SoftEtherVPN/tree/master/src/vpnserver)
  * SEIL (http://www.seil.jp/support/tech/doc/function/pppac/sstp_about.html)

Current client implementations:
  * Microsoft Windows (>Vista SP1 & Server 2008/2012)
  * MikroTik RouterOS
  * SoftEther VPN
  * sstp-client (http://sstp-client.sourceforge.net/)
  * SSToPer (https://github.com/hugsy/sstoper)

Further information:
  * http://msdn.microsoft.com/en-us/library/cc247338.aspx
  * http://support.microsoft.com/kb/947054

Related research:
    * Analysis Protocol SSTP Microsoft (http://www.hsc.fr/ressources/breves/sstp.html)

### SSTP Protocol Layers
```
   +-------------------+
   |                   |
   |       PPP         |
   |                   |
   +-------------------+
   |                   |
   |       SSTP        |
   |                   |
   +-------------------+
   |                   |
   |       HTTP        |
   |                   |
   +-------------------+
   |                   |
   |       SSL         |
   |                   |
   +-------------------+
   |                   |
   |      TCP/IP       |
   |                   |
   +-------------------+
```

### Nmap Scripts

#### sstp-info.nse
This script can be used to check if SSTP is supported on a given host.

Sample output:
```
[ ~/temp ] nmap --script sstp-info -p443 172.24.10.30   

Starting Nmap 6.41SVN ( http://nmap.org ) at 2013-11-02 01:35 CET
Nmap scan report for vpn1.contoso.com (172.24.10.30)
Host is up (0.0010s latency).
PORT    STATE SERVICE
443/tcp open  https
| sstp-info: 
|   status: SSTP is supported
|_  info: For more information, visit: http://msdn.microsoft.com/en-us/library/cc247338.aspx
```

### Scapy Template

Scapy SSTP layer, currently implemented control messages:
  * SSTP_MSG_CALL_CONNECT_REQUEST
  * SSTP_MSG_CALL_CONNECT_ACK
  * SSTP_MSG_CALL_CONNECT_NAK
  * SSTP_MSG_CALL_ABORT
  * SSTP_MSG_CALL_DISCONNECT
  * SSTP_MSG_CALL_DISCONNECT_ACK
  * SSTP_MSG_ECHO_REQUEST
  * SSTP_MSG_ECHO_RESPONSE

Not yet supported control messages:
  * SSTP_MSG_CALL_CONNECTED

#### sstp-negotiation.py
This is a test script that executes three steps in order to establish the SSTP layer:
  * Creating of a SSL socket
  * HTTP layer negotiation
  * SSTP layer negotiation

Note: This code is highly experimental!
