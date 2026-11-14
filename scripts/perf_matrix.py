#!/usr/bin/env python3
"""
Comprehensive performance measurement suite for xray-rs optimizations.
Measures:
  1. Memory (Peak RSS in KiB / MiB)
  2. CPU consumption (utime + stime ticks)
  3. Throughput (MB/s for TCP, packets/sec for UDP)
  4. Concurrent connection latency & churn
"""

import os
import sys
import time
import json
import socket
import subprocess
import threading
import concurrent.futures

def get_proc_metrics(pid):
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            lines = f.readlines()
        rss = 0
        for line in lines:
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1]) # in KiB
                break
        with open(f"/proc/{pid}/stat", "r") as f:
            parts = f.read().split()
            utime = int(parts[13])
            stime = int(parts[14])
        return {"rss_kib": rss, "cpu_ticks": utime + stime}
    except Exception:
        return {"rss_kib": 0, "cpu_ticks": 0}

def test_tcp_throughput(proxy_port, total_bytes=200*1024*1024):
    """Measures raw TCP stream throughput through SOCKS5 proxy."""
    received_bytes = [0]
    stop_event = threading.Event()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    target_port = s.getsockname()[1]
    s.listen(1)
    s.settimeout(1.0)
    
    def target_server():
        while not stop_event.is_set():
            try:
                conn, _ = s.accept()
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    received_bytes[0] += len(data)
                conn.close()
            except socket.timeout:
                continue
        s.close()
        
    t = threading.Thread(target=target_server, daemon=True)
    t.start()
    time.sleep(0.1)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", proxy_port))
    client.sendall(b"\x05\x01\x00")
    client.recv(2)
    port_bytes = target_port.to_bytes(2, "big")
    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port_bytes)
    resp = client.recv(10)
    assert resp[1] == 0, f"SOCKS5 connect failed: {resp}"
    
    chunk = b"X" * 65536
    sent = 0
    t0 = time.perf_counter()
    while sent < total_bytes:
        to_send = min(len(chunk), total_bytes - sent)
        client.sendall(chunk[:to_send])
        sent += to_send
    client.shutdown(socket.SHUT_WR)
    
    while received_bytes[0] < total_bytes and time.perf_counter() - t0 < 10.0:
        time.sleep(0.005)
    t1 = time.perf_counter()
    
    client.close()
    stop_event.set()
    t.join()
    
    elapsed = t1 - t0
    mb_per_sec = (sent / (1024 * 1024)) / elapsed if elapsed > 0 else 0
    return {"elapsed_s": elapsed, "mb_per_sec": mb_per_sec, "bytes": sent}

def test_concurrent_churn(proxy_port, num_conns=200):
    """Opens and transfers data across num_conns concurrent connections to stress allocator."""
    stop_event = threading.Event()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    target_port = s.getsockname()[1]
    s.listen(512)
    s.settimeout(0.5)
    
    def target_server():
        while not stop_event.is_set():
            try:
                conn, _ = s.accept()
                def handler(c):
                    try:
                        c.settimeout(1.0)
                        data = c.recv(1024)
                        c.sendall(b"OK:" + data)
                        c.close()
                    except Exception:
                        pass
                threading.Thread(target=handler, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        s.close()

    t = threading.Thread(target=target_server, daemon=True)
    t.start()
    time.sleep(0.1)

    port_bytes = target_port.to_bytes(2, "big")
    
    def worker(idx):
        try:
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(2.0)
            c.connect(("127.0.0.1", proxy_port))
            c.sendall(b"\x05\x01\x00")
            c.recv(2)
            c.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + port_bytes)
            c.recv(10)
            c.sendall(b"PING" + str(idx).encode())
            c.recv(1024)
            c.close()
            return True
        except Exception:
            return False

    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        results = list(executor.map(worker, range(num_conns)))
    t1 = time.perf_counter()

    stop_event.set()
    t.join()

    successes = sum(1 for r in results if r)
    return {
        "conns": num_conns,
        "successes": successes,
        "elapsed_s": t1 - t0,
        "conns_per_sec": num_conns / (t1 - t0) if t1 > t0 else 0
    }

def test_udp_rate(proxy_port, target_port, num_packets=10000):
    """Sends num_packets UDP datagrams through SOCKS5 UDP associate."""
    stop_event = threading.Event()
    received_count = [0]
    
    def target_udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", target_port))
        s.settimeout(0.5)
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(2048)
                received_count[0] += 1
                s.sendto(b"ECHO:" + data, addr)
            except socket.timeout:
                continue
        s.close()
        
    t = threading.Thread(target=target_udp, daemon=True)
    t.start()
    time.sleep(0.1)
    
    ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl.connect(("127.0.0.1", proxy_port))
    ctrl.sendall(b"\x05\x01\x00")
    ctrl.recv(2)
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    resp = ctrl.recv(10)
    assert resp[1] == 0, f"UDP ASSOCIATE failed: {resp}"
    relay_port = int.from_bytes(resp[8:10], "big")
    
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target_port_bytes = target_port.to_bytes(2, "big")
    hdr = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + target_port_bytes
    payload = b"U" * 512
    packet = hdr + payload
    
    t0 = time.perf_counter()
    for _ in range(num_packets):
        udp_sock.sendto(packet, ("127.0.0.1", relay_port))
    
    timeout_t = time.perf_counter() + 2.0
    while received_count[0] < num_packets and time.perf_counter() < timeout_t:
        time.sleep(0.01)
    t1 = time.perf_counter()
    
    udp_sock.close()
    ctrl.close()
    stop_event.set()
    t.join()
    
    elapsed = t1 - t0
    pps = received_count[0] / elapsed if elapsed > 0 else 0
    return {
        "packets_sent": num_packets,
        "packets_received": received_count[0],
        "elapsed_s": elapsed,
        "pps": pps
    }

def wait_for_port(port, timeout=3.0):
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return True
        except OSError:
            time.sleep(0.05)
    return False

def run_suite(binary_path):
    import json
    import tempfile
    
    proxy_port = 29808
    target_port = 29809
    
    cfg = {
      "log": {"loglevel": "warning"},
      "inbounds": [{"tag": "socks-in", "port": proxy_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
      "outbounds": [{"tag": "direct", "protocol": "freedom"}]
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_file = f.name
        
    proc = subprocess.Popen([binary_path, "-c", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if not wait_for_port(proxy_port):
        err = proc.stderr.read() if proc.stderr else ""
        proc.kill()
        raise RuntimeError(f"Server did not start on {proxy_port}: {err}")
    
    try:
        pid = proc.pid
        idle_m = get_proc_metrics(pid)
        
        # 1. TCP Throughput (100 MB)
        tcp = test_tcp_throughput(proxy_port, total_bytes=100*1024*1024)
        
        # 2. Concurrency Churn (200 conns)
        churn = test_concurrent_churn(proxy_port, num_conns=200)
        
        peak_m = get_proc_metrics(pid)
        
        res = {
            "binary": binary_path,
            "tcp_mb_s": round(tcp["mb_per_sec"], 2),
            "churn_conns_s": round(churn["conns_per_sec"], 1),
            "idle_rss_mib": round(idle_m["rss_kib"] / 1024, 2),
            "peak_rss_mib": round(peak_m["rss_kib"] / 1024, 2),
            "cpu_ticks": peak_m["cpu_ticks"] - idle_m["cpu_ticks"],
        }
        return res
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            os.remove(cfg_file)
        except OSError:
            pass

if __name__ == "__main__":
    bin_path = sys.argv[1] if len(sys.argv) > 1 else "target/release/xray-server"
    res = run_suite(bin_path)
    print(json.dumps(res, indent=2))

