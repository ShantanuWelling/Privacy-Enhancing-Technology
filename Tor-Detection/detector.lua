-- Wireshark Lua plugin to detect Tor network traffic

-- Create a new protocol
local tor_proto = Proto("tor_detect", "Tor Traffic Detector")

local tor_status_field = ProtoField.string("tor_detect.status", "Tor Status")

tor_proto.fields = { tor_status_field }

local function load_tor_relays(filename)
    local relays = {}
    local file = io.open(filename, "r")
    if file then
        for line in file:lines() do
            relays[line] = true
        end
        file:close()
    else
        print("Failed to open file: " .. filename)
    end
    return relays
end

-- List of known Tor relay IPs (should be updated dynamically)
local tor_relays = load_tor_relays("C:\\Users\\Shantanu Welling\\Documents\\IIT Bombay\\CS790\\Privacy-Enhancing-Technology\\Tor-Detection\\tor_relays.txt")

local tor_flagged_ips = {}

local tls_handshake_type = Field.new("tls.handshake.type")
local cipher_suites_len = Field.new("tls.handshake.cipher_suites_length")
local cipher_suites = Field.new("tls.handshake.ciphersuites")

-- Tor-specific cipher suites (18 in total)
local tor_cipher_suites = {
    0x1302, 0x1303, 0x1301, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
    0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x0033,
    0x0039, 0x002f, 0x0035, 0x00ff
}

-- Convert the cipher suite list into a lookup table
local tor_cipher_lookup = {}

for _, v in ipairs(tor_cipher_suites) do
    tor_cipher_lookup[v] = true
end

-- Function to check if all 18 cipher suites match Tor's fingerprint
local function is_tor_cipher_match(cipher_suites)
    local cipher_values = {}
    for i = 1, cipher_suites:len(), 2 do
        local suite = cipher_suites:range(i - 1, 2):uint()
        table.insert(cipher_values, suite)
        -- print("Cipher Suite: " .. string.format("0x%04x", suite))
    end
    if #cipher_values ~= 18 then
        return false
    end
    for _, v in ipairs(cipher_values) do
        if not tor_cipher_lookup[v] then
            return false
        end
    end
    return true
end

-- Function to detect Tor traffic
function tor_proto.dissector(buffer, pinfo, tree)
    -- print("Dissector called for packet: " .. tostring(pinfo.number))

    local src_ip = tostring(pinfo.net_src) 
    local dst_ip = tostring(pinfo.net_dst)

    -- print("Source IP: " .. src_ip .. ", Destination IP: " .. dst_ip)

    -- Check if IP is a known Tor relay
    local is_tor_traffic = tor_relays[dst_ip] or tor_relays[src_ip]
    -- local is_tor_traffic = false
    
    if not is_tor_traffic then
        if tor_flagged_ips[src_ip] or tor_flagged_ips[dst_ip] then
            is_tor_traffic = true
        else
            local handshake_type = tls_handshake_type() 
            local ciphersuite_len = cipher_suites_len()
            local ciphers = cipher_suites()

            if handshake_type and handshake_type.value == 1 and ciphersuite_len and ciphers then  -- Client Hello
                if ciphersuite_len.value == 36 and is_tor_cipher_match(ciphers.range) then -- Tor uses 18 suites (36 bytes total)
                    -- Store detected IPs
                    -- print("Tor traffic detected: " .. src_ip .. " to " .. dst_ip)
                    tor_flagged_ips[dst_ip] = true
                    is_tor_traffic = true
                end
            end
        end
    end
    
    
    local subtree = tree:add(tor_proto, "Tor Traffic Detection")

    if is_tor_traffic then
        -- Add a "Tor!" label to the packet's subtree in Wireshark's tree
        subtree:add(tor_status_field, "Tor!")
        pinfo.cols.info:append(" [Tor Traffic Detected!!]")
        set_color_filter_slot(1, "tor_detect.status == \"Tor!\"")
    else
        subtree:add(tor_status_field, "")
    end   
end

-- Register the dissector for TCP and TLS traffic
-- local tcp_port = DissectorTable.get("tcp.port")
-- tcp_port:add(443, tor_proto) -- Common Tor usage over TLS

-- tcp_port:add(9001, tor_proto) -- Tor relay default port
-- tcp_port:add(9050, tor_proto) -- Tor SOCKS proxy port

register_postdissector(tor_proto)