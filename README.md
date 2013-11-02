sstp-tools
==========

### SSTP Info
Current implementations:
  * Microsoft Windows (Server 2008/Server 2012)
  * MikroTik RouterOS

Further information:
  * http://msdn.microsoft.com/en-us/library/cc247338.aspx
  * http://support.microsoft.com/kb/947054

### Nmap NSE Scripts

#### sstp-discover.nse
Check if SSTP is supported.

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

