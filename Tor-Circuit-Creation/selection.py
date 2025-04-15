import stem.control
import stem
import copy
import pycurl
import random
from stem.control import Controller
from io import BytesIO
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from collections import defaultdict

DEFAULT_WEIGHT = 10000
fingerprint_to_family = defaultdict(set)

def weighted_random_choice(nodes, weight_fn):
    total = sum(weight_fn(n) for n in nodes)
    if total == 0:
        return None
    r = random.uniform(0, total)
    upto = 0
    for node in nodes:
        w = weight_fn(node)
        if upto + w >= r:
            return node
        upto += w
    return None

def query(url):
    output = BytesIO()
    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, 9050)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.CONNECTTIMEOUT, 20)
    query.setopt(pycurl.WRITEFUNCTION, output.write)

    try:
        query.perform()
        status_code = query.getinfo(pycurl.HTTP_CODE)
        return status_code, output.getvalue().decode('utf-8')
    except pycurl.error as exc:
        raise ValueError("Unable to reach %s (%s)" % (url, exc))

def in_same_16_subnet(ip1, ip2):
    return ip1.split('.')[:2] == ip2.split('.')[:2]


def select_exit(nodes):
    exit_node = None
    candidates = [n for n in nodes if "Exit" in n.flags and "BadExit" not in n.flags]
    # Remove BadExit as per user preferences SW
    # Unless requested to do so by the user, we never choose an exit node flagged as "BadExit"
    def exit_weight(n):
        bw = n.bandwidth or 1
        if "Guard" in n.flags:
            return get_weight("d", "e") * bw
        return get_weight("e", "e") * bw
    
    exit_node = weighted_random_choice(candidates, exit_weight)
    if exit_node:
        nodes.remove(exit_node)
    else:
        print("[-] No exit node found.")
        return None, None
    return exit_node, nodes

def select_guard(nodes, exit_node_address, exit_node_family):
    guard_node = None
    candidates = [n for n in nodes if "Guard" in n.flags and not in_same_16_subnet(n.address, exit_node_address) and fingerprint_to_family[n.fingerprint].isdisjoint(exit_node_family)]
    def guard_weight(n):
        bw = n.bandwidth or 1
        if "Exit" in n.flags:
            return get_weight("d", "g") * bw
        return get_weight("g", "g") * bw
    guard_node = weighted_random_choice(candidates, guard_weight)
    if guard_node:
        nodes.remove(guard_node)
    else:
        print("[-] No guard node found.")
        return None, None
    return guard_node, nodes

def select_middle(nodes, exit_node_address, guard_node_address, exit_node_family, guard_node_family):
    middle_node = None    
    candidates = [n for n in nodes if not in_same_16_subnet(n.address, exit_node_address)
                  and not in_same_16_subnet(n.address, guard_node_address) and
                  fingerprint_to_family[n.fingerprint].isdisjoint(exit_node_family) and fingerprint_to_family[n.fingerprint].isdisjoint(guard_node_family)]
    def middle_weight(n):
        bw = n.bandwidth or 1
        if "Guard" in n.flags and "Exit" in n.flags:
            return get_weight("d", "m") * bw
        elif "Guard" in n.flags:
            return get_weight("g", "m") * bw
        elif "Exit" in n.flags:
            return get_weight("e", "m") * bw
        else:
            return get_weight("m", "m") * bw
    middle_node = weighted_random_choice(candidates, middle_weight)
    if middle_node:
        nodes.remove(middle_node)
    else:
        print("[-] No middle node found.")
        return None, None
    return middle_node, nodes

def select_path(nodes):
    guard_node = None
    exit_node = None
    middle_node = None
    ips = {}
    hostnames = {}
    
    # select exit node
    exit_node_object, nodes = select_exit(nodes)
    if not exit_node_object:
        return None, None, None, None, None
    exit_node = exit_node_object.fingerprint
    ips["Exit"] = exit_node_object.address
    hostnames["Exit"] = exit_node_object.nickname
    
    # select guard node
    guard_node_object, nodes = select_guard(nodes, ips["Exit"], fingerprint_to_family[exit_node])
    if not guard_node_object:
        return None, None, None, None, None
    guard_node = guard_node_object.fingerprint
    ips["Guard"] = guard_node_object.address
    hostnames["Guard"] = guard_node_object.nickname
    
    # select middle node
    middle_node_object, nodes = select_middle(nodes, ips["Exit"], ips["Guard"], fingerprint_to_family[exit_node], fingerprint_to_family[guard_node])
    if not middle_node_object:
        return None, None, None, None, None
    middle_node = middle_node_object.fingerprint
    ips["Middle"] = middle_node_object.address
    hostnames["Middle"] = middle_node_object.nickname
    
    return guard_node, exit_node, middle_node, ips, hostnames
 
with open("/root/.tor/cached-consensus", "rb") as f:
    consensus = NetworkStatusDocumentV3(f.read())
    bw_weights = consensus.bandwidth_weights
    # print(bw_weights)
    
with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    
    def get_weight(flag_combo, pos):
        try:
            key = f"W{pos[0].lower()}{flag_combo}"
            return bw_weights[key]
        except Exception:
            print("Exception in Get weight")
            return DEFAULT_WEIGHT
    
    # Get a list of relays
    print("[*] Fetching relay fingerprints...")
    nodes = []
    for node in controller.get_network_statuses():
        if "StaleDesc" in node.flags or "Stable" not in node.flags or "Running" not in node.flags or "Valid" not in node.flags:
            # Add "Fast" flag to the filter as per user preferences SW
            # For "fast" circuits, we only choose nodes with the Fast flag. 
            # For non-"fast" circuits, all nodes are eligible.
            continue
        nodes.append(node)
    
    for server_desc in controller.get_server_descriptors():
        fingerprint = server_desc.fingerprint
        family = server_desc.family
        if family:
            fingerprint_to_family[fingerprint].update(family)
        
    circuit_id = None
    while True:
        guard_node, exit_node, middle_node, ips, hostnames = select_path(copy.deepcopy(nodes))
        
        if not guard_node or not exit_node or not middle_node:
            print("[-] Failed to select path. Retrying...")
            continue

        path = [guard_node, middle_node, exit_node]
        print(f"[+] Building 3-hop circuit: {path}")

        try:
            circuit_id = controller.new_circuit(path, await_build=True, timeout=10)
            print(f"[+] Built circuit with ID: {circuit_id}")
            print(f"\n[+] Circuit path:")
            print(f"[+] 1) Guard:   {hostnames['Guard'].ljust(20, ' ')} \t {ips['Guard']}")
            print(f"[+] 2) Middle:  {hostnames['Middle'].ljust(20, ' ')} \t {ips['Middle']}")
            print(f"[+] 3) Exit:    {hostnames['Exit'].ljust(20, ' ')} \t {ips['Exit']}\n")
            break
        except Exception as e:
            print("[-] Failed to build circuit:", e)
            print("[-] Retrying...")
            
    attached = False
    def attach_stream(stream):
        global attached
        if stream.status == "NEW" and not attached:
            print(f"[DEBUG] Attaching stream {stream.id} to circuit {circuit_id}")
            try:
                attached = True
                controller.attach_stream(stream.id, circuit_id)
            except Exception as e:
                print(f"[-] Failed to attach stream {stream.id} to circuit {circuit_id}: {e}")
                attached = False
        print(f"[DEBUG] Stream {stream.id} - Status: {stream.status} | Target: {stream.target_address}:{stream.target_port} | Circuit: {circuit_id}")
        print(stream)

    controller.add_event_listener(attach_stream, stem.control.EventType.STREAM)
    
    controller.set_conf("__LeaveStreamsUnattached", "1")

    print("[*] Using SOCKS proxy to send request through custom circuit...")
    
    status_code, response = query("https://www.example.com")
    print("[+] Response Status Code:", status_code)
    print("[+] Response:", response[:500])
    
    controller.remove_event_listener(attach_stream)
    controller.reset_conf("__LeaveStreamsUnattached")
    # controller.close_circuit(circuit_id)
    # print("[+] Circuit closed.")
    # controller.close()
