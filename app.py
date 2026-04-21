from flask import Flask, render_template, request, jsonify
import socket
import threading
from queue import Queue
from datetime import datetime

app = Flask(__name__)

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

def scan_port(ip, port, results, lock):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = get_service(port)
            with lock:
                results.append({"port": port, "service": service, "status": "OPEN"})
        sock.close()
    except:
        pass

def run_scan(target, start, end):
    results = []
    lock = threading.Lock()
    queue = Queue()
    
    for port in range(start, end + 1):
        queue.put(port)
    
    def worker():
        while not queue.empty():
            port = queue.get()
            scan_port(target, port, results, lock)
            queue.task_done()
    
    threads = []
    for _ in range(100):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    queue.join()
    return sorted(results, key=lambda x: x["port"])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target")
    start = int(data.get("start", 1))
    end = int(data.get("end", 100))
    
    start_time = datetime.now()
    results = run_scan(target, start, end)
    duration = (datetime.now() - start_time).seconds
    
    return jsonify({
        "target": target,
        "results": results,
        "total_open": len(results),
        "duration": duration,
        "scan_time": str(datetime.now())
    })

if __name__ == "__main__":
    app.run(debug=True)