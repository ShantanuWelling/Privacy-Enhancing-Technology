-- Wireshark Lua plugin to detect Tor network traffic

-- Create a new protocol
local tor_proto = Proto("tor_detect", "Tor Traffic Detector")


local function load_tor_relays(filename)
    local relays = {}
    local file = io.open(filename, "r")
    if file then
        for line in file:lines() do
            relays[line] = true
            -- print("Loaded Tor IP: " .. line)
        end
        file:close()
    else
        print("Failed to open file: " .. filename)
    end
    return relays
end

-- List of known Tor relay IPs (example, should be updated dynamically)
local tor_relays = load_tor_relays("C:\\Users\\Shantanu Welling\\Documents\\IIT Bombay\\CS790\\Privacy-Enhancing-Technology\\Tor-Detection\\tor_relays.txt")


-- Function to detect Tor traffic
function tor_proto.dissector(buffer, pinfo, tree)
    -- print("Dissector called for packet: " .. tostring(pinfo.number))

    local src_ip = tostring(pinfo.net_src) -- Alternative way to get IP
    local dst_ip = tostring(pinfo.net_dst)

    -- print("Source IP: " .. src_ip .. ", Destination IP: " .. dst_ip)

    -- Check if destination IP is a known Tor relay
    if tor_relays[dst_ip] or tor_relays[src_ip] then
        -- print("Tor traffic detected: " .. (tor_relays[src_ip] and src_ip or dst_ip))
        pinfo.cols.protocol = "TOR"
        pinfo.cols.info = "Tor!"
        local subtree = tree:add(tor_proto, buffer(), "Tor Traffic Detected")
        subtree:add("Tor relay detected: " .. dst_ip)
    else
        print("No Tor traffic detected for source: " .. src_ip .. " and destination: " .. dst_ip)
    end
end

-- Register the dissector for TCP and TLS traffic
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(443, tor_proto) -- Common Tor usage over TLS

tcp_port:add(9001, tor_proto) -- Tor relay default port
tcp_port:add(9050, tor_proto) -- Tor SOCKS proxy port
