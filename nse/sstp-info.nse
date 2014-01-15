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
    - MikroTik RouterOS

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
-- |   STATUS: SSTP is supported!
-- |   SERVER: Microsoft-HTTPAPI/2.0
-- |   TIMESTAMP: Tue, 14 Jan 2014 23:57:32 GMT
-- |_  INFO: For more information, visit: http://msdn.microsoft.com/en-us/library/cc247338.aspx

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

portrule = shortport.port_or_service({443}, {"https"})

local function buildRequest(host)
    local hostfield, request

    if host.targetname then
       hostfield = host.targetname
    else
        hostfield = host.ip
    end

    request = 'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\n'
    request = request .. 'Host: ' .. hostfield .. '\n'
    request = request .. 'SSTPCORRELATIONID: {}\n' -- This is not really necessary
    request = request .. 'Content-Length: 18446744073709551615\n\n'
    return request
end

action = function(host, port)
    try = nmap.new_try(function() socket:close() end)
    local socket = comm.tryssl(host,port)
    local request = buildRequest(host)
    try(socket:send(request))
    local response = try(socket:receive())
    socket:close()
    local output = stdnse.output_table()

    if response then
        if string.match (response, 'HTTP/1.1 200') then
            output.STATUS = 'SSTP is supported!'
            output.SERVER = string.match(response, 'Server: ([%w-/.]+)')
            output.TIMESTAMP = string.match(response, 'Date: ([%d%w-/.:, ]+)')
            output.INFO = 'For more information, visit: http://msdn.microsoft.com/en-us/library/cc247338.aspx'
            return output
        end
    end
end
