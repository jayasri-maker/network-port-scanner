import socket
import threading
import subprocess
import platform
from datetime import datetime
from queue import Queue

def get_service(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 135: "RPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5900: "VNC",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    return services.get(port, "Unknown")

def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:50] if banner else "N/A"
    except:
        return "N/A"

def ping_host(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    result = subprocess.run(
        ["ping", param, "1", host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

open_ports = []
lock = threading.Lock()

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = get_service(port)
            banner = grab_banner(ip, port)
            with lock:
                open_ports.append((port, service, banner))
                print(f"  [OPEN] Port {port:5d} | {service:12s} | Banner: {banner}")
        sock.close()
    except:
        pass

def worker(ip, queue):
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port)
        queue.task_done()

def generate_report(target, open_ports, start, end):
    filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    rows = ""
    for port, service, banner in sorted(open_ports):
        rows += f"<tr><td>{port}</td><td class='open'>OPEN</td><td>{service}</td><td>{banner}</td></tr>"
    
    html = """<!DOCTYPE html>
<html>
<head>
<title>Port Scan Report</title>
<style>
body { font-family: Arial; background: #1a1a2e; color: #eee; padding: 20px; }
h1 { color: #00d4ff; }
table { width: 100%; border-collapse: collapse; margin-top: 20px; }
th { background: #00d4ff; color: #000; padding: 10px; }
td { padding: 10px; border-bottom: 1px solid #333; }
tr:hover { background: #16213e; }
.open { color: #00ff88; font-weight: bold; }
.info { background: #16213e; padding: 15px; border-radius: 8px; margin: 10px 0; }
</style>
</head>
<body>
<h1>Network Port Scanner Report</h1>
<div class='info'>
<p><b>Target:</b> """ + target + """</p>
<p><b>Port Range:</b> """ + str(start) + " - " + str(end) + """</p>
<p><b>Scan Time:</b> """ + str(datetime.now()) + """</p>
<p><b>Open Ports:</b> """ + str(len(open_ports)) + """</p>
</div>
<table>
<tr><th>Port</th><th>Status</th><th>Service</th><th>Banner</th></tr>
""" + rows + """
</table>
</body>
</html>"""
    
    with open(filename, "w") as f:
        f.write(html)
    return filename

print("=" * 55)
print("      ADVANCED NETWORK PORT SCANNER")
print("=" * 55)

target = input("\nEnter IP address or hostname: ")
start = int(input("Start port (e.g. 1): "))
end = int(input("End port (e.g. 500): "))
threads = int(input("Threads (e.g. 100): "))

print(f"\n[*] Checking if {target} is online...")
if not ping_host(target):
    print(f"[!] {target} seems offline. Continuing anyway...")
else:
    print(f"[+] {target} is online!")

print(f"\n[*] Scanning ports {start}-{end} with {threads} threads...\n")
start_time = datetime.now()

queue = Queue()
for port in range(start, end + 1):
    queue.put(port)

thread_list = []
for _ in range(threads):
    t = threading.Thread(target=worker, args=(target, queue))
    t.daemon = True
    t.start()
    thread_list.append(t)

queue.join()

end_time = datetime.now()
duration = (end_time - start_time).seconds

print(f"\n{'=' * 55}")
print(f"[+] Scan Complete! Time taken: {duration} seconds")
print(f"[+] Total Open Ports: {len(open_ports)}")

if open_ports:
    report = generate_report(target, open_ports, start, end)
    print(f"[+] HTML Report saved: {report}")

print("=" * 55)