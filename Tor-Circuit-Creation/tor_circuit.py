from stem.control import Controller
import stem.control
import stem
import random
import pycurl
from io import BytesIO

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



def get_path(nodes):
    guard_node = None
    exit_node = None
    middle_nodes = []
    ips = {}
    hostnames = {}
    while not guard_node or not exit_node or len(middle_nodes) < 2:
        node = random.choice(nodes)
        if node.fingerprint == guard_node or node.fingerprint == exit_node or node.fingerprint in middle_nodes:
            continue
        if "Valid" not in node.flags or "Stable" not in node.flags or "Running" not in node.flags or "BadExit" in node.flags:
            continue
        if not guard_node and "Guard" in node.flags:
            guard_node = node.fingerprint
            ips["Guard"] = node.address
            hostnames["Guard"] = node.nickname
        elif not exit_node and "Exit" in node.flags:
            exit_node = node.fingerprint
            ips["Exit"] = node.address
            hostnames["Exit"] = node.nickname
        elif len(middle_nodes) < 2:
            middle_nodes.append(node.fingerprint)
            if len(middle_nodes) == 1:
                ips["Middle1"] = node.address
                hostnames["Middle1"] = node.nickname
            else:
                ips["Middle2"] = node.address
                hostnames["Middle2"] = node.nickname
        # Ensure we have a valid path
        if guard_node and exit_node and len(middle_nodes) == 2:
            break
    return guard_node, exit_node, middle_nodes, ips, hostnames
    
with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    

    # Get a list of relays
    print("[*] Fetching relay fingerprints...")
    nodes = []
    for node in controller.get_network_statuses():
        nodes.append(node)
        # print(node.flags)
    circuit_id = None
    while True:
        guard_node, exit_node, middle_nodes, ips, hostnames = get_path(nodes)
        if not guard_node or not exit_node or len(middle_nodes) != 2:
            print("[-] Could not find enough relays.")
            exit(1)

        path = [guard_node] + middle_nodes + [exit_node]
        print(f"[+] Building 4-hop circuit: {path}")

        try:
            circuit_id = controller.new_circuit(path, await_build=True, timeout=10)
            print(f"[+] Built circuit with ID: {circuit_id}")
            print(f"\n[+] Circuit path:")
            print(f"[+] 1) Guard:   {hostnames['Guard'].ljust(20, ' ')} \t {ips['Guard']}")
            print(f"[+] 2) Middle1: {hostnames['Middle1'].ljust(20, ' ')} \t {ips['Middle1']}")
            print(f"[+] 3) Middle2: {hostnames['Middle2'].ljust(20, ' ')} \t {ips['Middle2']}")
            print(f"[+] 4) Exit:    {hostnames['Exit'].ljust(20, ' ')} \t {ips['Exit']}\n")
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
