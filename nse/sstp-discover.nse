local nmap = require('nmap')
local string = require('string')
local stdnse = require('stdnse')

description = [[
Check if SSTP is supported.

Current implementations:
    - Microsoft Windows (Server 2008/Server 2012)
    - MikroTik RouterOS

SSTP specification: http://msdn.microsoft.com/en-us/library/cc247338.aspx
Info about the default URI (ServerUri): http://support.microsoft.com/kb/947054
]]

--
--@output
-- 443/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
-- | sstp-discover: 
-- |   Status: SSTP is supported!
-- |   Server: Microsoft-HTTPAPI/2.0
-- |_  Timestamp: Fri, 01 Nov 2013 09:43:14 GMT

author = "Niklaus Schiess"

categories = {'safe', 'discovery'}

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


function portrule(host, port)
    return port.number == 443
end

-- Return SSL socket object
local function getSSLSocket(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(1000)
    try = nmap.new_try(function() socket:close() end)
    try(socket:connect(host.ip, port.number))
    try(socket:reconnect_ssl())
    return socket
end

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

-- Send SSTP negotiation request and close the SSL socket
local function SSTPNegotiation(socket, request)
    try(socket:send(request))
    response = try(socket:receive())
    socket:close()
    return response
end

action = function(host, port)
    local socket = getSSLSocket(host, port)
    local request = buildRequest(host)
    local response = SSTPNegotiation(socket, request)
    local output = stdnse.output_table()

    if (response) then
        if string.match (response, 'HTTP/1.1 200') then
            output.status = 'SSTP is supported!'
            output.server = string.match(response, 'Server: ([%w-/.]+)')
            output.timestamp = string.match(response, 'Date: ([%d%w-/.:, ]+)')
        end
    end
    return output
end
