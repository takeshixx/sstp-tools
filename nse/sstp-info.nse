local nmap = require('nmap')
local comm = require('comm')
local string = require('string')
local stdnse = require('stdnse')
local shortport = require('shortport')

description = [[
Check if the Secure Socket Tunneling Protocol is supported. This is
accomplished by trying to establish the HTTPS layer which is used to
carry SSTP traffic as described in:
    - http://msdn.microsoft.com/en-us/library/cc247364.aspx

Current SSTP server implementations:
    - Microsoft Windows (Server 2008/Server 2012)
    - MikroTik RouterOS (http://wiki.mikrotik.com/wiki/Manual:Interface/SSTP)
    - SoftEther (https://github.com/SoftEtherVPN/SoftEtherVPN/)
    - SEIL (http://www.seil.jp)

SSTP specification:
    _ http://msdn.microsoft.com/en-us/library/cc247338.aspx

Info about the default URI (ServerUri):
    - http://support.microsoft.com/kb/947054

SSTP Remote Access Step-by-Step Guide: Deployment:
    - http://technet.microsoft.com/de-de/library/cc731352(v=ws.10).aspx

SSTP enabled hosts (for testing purposes):
    - http://billing.purevpn.com/sstp-manual-setup-hostname-list.php
]]

author = "takeshix@adversec.com"
categories = {'safe', 'default'}

--
--@output
-- 443/tcp open  https
-- | sstp-info: 
-- |   status: SSTP is supported.
-- |_  info: For more information, visit: http://msdn.microsoft.com/en-us/library/cc247338.aspx

-- SSTP negotiation response (Windows)
--
-- HTTP/1.1 200 
-- Content-Length: 18446744073709551615
-- Server: Microsoft-HTTPAPI/2.0
-- Date: Fri, 01 Nov 2013 00:00:00 GMT

-- SSTP negotiation response (Mikrotik RouterOS)
--
-- HTTP/1.1 200 
-- Content-Length: 18446744073709551615
-- Server: MikroTik-SSTP
-- Date: Fri, 01 Nov 2013 00:00:00 GMT

portrule = function(host, port)
  return shortport.http(host, port) and shortport.ssl(host, port)
end 
  
local request = 'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75} HTTP/1.1\r\nHost: %s\r\nSSTPCORRELATIONID: {}\r\n\r\nContent-Length: 18446744073709551615\r\n\r\n'

action = function(host, port)
    local output = stdnse.output_table()
    local socket, response = comm.tryssl(host,port,string.format(request, host.targetname or host.ip))
    if not socket then return nil end
    stdnse.print_debug(1,'HTTPS layer establishment response:\n\n%s',response)

    if string.match(response, 'HTTP/1.1 200') then
            output.status = 'SSTP is supported.'
            output.info = 'For more information, visit: http://msdn.microsoft.com/en-us/library/cc247338.aspx'
            return output
    end
end
