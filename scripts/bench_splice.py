#!/usr/bin/env python3
import os
import socket
import time
import threading

TOTAL_BYTES = 200 * 1024 * 1024 # 200 MB

def make_tcp_pair():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    server, _ = listener.accept()
    listener.close()
    return server, client

def test_userspace_copy():
    r_sock, w_sock = make_tcp_pair()
    sink_sock, relay_in = make_tcp_pair()
    
    stop_event = threading.Event()
    def sink():
        while not stop_event.is_set():
            try:
                d = sink_sock.recv(65536)
                if not d:
                    break
            except Exception:
                break
    t_sink = threading.Thread(target=sink, daemon=True)
    t_sink.start()
    
    def sender():
        chunk = b"A" * 65536
        sent = 0
        while sent < TOTAL_BYTES:
            n = w_sock.send(chunk[:min(len(chunk), TOTAL_BYTES - sent)])
            sent += n
        w_sock.close()
        
    t_send = threading.Thread(target=sender, daemon=True)
    t_send.start()
    
    buf = bytearray(65536)
    moved = 0
    t0 = time.process_time()
    wall0 = time.perf_counter()
    while moved < TOTAL_BYTES:
        n = r_sock.recv_into(buf)
        if not n:
            break
        relay_in.sendall(buf[:n])
        moved += n
    wall1 = time.perf_counter()
    cpu1 = time.process_time()
    
    stop_event.set()
    t_send.join()
    r_sock.close()
    relay_in.close()
    sink_sock.close()
    return {"wall_s": wall1 - wall0, "cpu_s": cpu1 - t0, "mb_s": (moved/1024/1024)/(wall1 - wall0)}

def test_kernel_splice():
    r_sock, w_sock = make_tcp_pair()
    sink_sock, relay_in = make_tcp_pair()
    
    stop_event = threading.Event()
    def sink():
        while not stop_event.is_set():
            try:
                d = sink_sock.recv(65536)
                if not d:
                    break
            except Exception:
                break
    t_sink = threading.Thread(target=sink, daemon=True)
    t_sink.start()
    
    def sender():
        chunk = b"A" * 65536
        sent = 0
        while sent < TOTAL_BYTES:
            n = w_sock.send(chunk[:min(len(chunk), TOTAL_BYTES - sent)])
            sent += n
        w_sock.close()
        
    t_send = threading.Thread(target=sender, daemon=True)
    t_send.start()
    
    pipe_r, pipe_w = os.pipe()
    import fcntl
    try:
        fcntl.fcntl(pipe_w, 1031, 1024*1024)
    except Exception:
        pass
        
    moved = 0
    t0 = time.process_time()
    wall0 = time.perf_counter()
    while moved < TOTAL_BYTES:
        n = os.splice(r_sock.fileno(), pipe_w, min(TOTAL_BYTES - moved, 1024*1024), flags=0)
        if n == 0:
            break
        in_pipe = n
        while in_pipe > 0:
            m = os.splice(pipe_r, relay_in.fileno(), in_pipe, flags=0)
            in_pipe -= m
        moved += n
    wall1 = time.perf_counter()
    cpu1 = time.process_time()
    
    stop_event.set()
    t_send.join()
    os.close(pipe_r)
    os.close(pipe_w)
    r_sock.close()
    relay_in.close()
    sink_sock.close()
    return {"wall_s": wall1 - wall0, "cpu_s": cpu1 - t0, "mb_s": (moved/1024/1024)/(wall1 - wall0)}

if __name__ == "__main__":
    u = test_userspace_copy()
    s = test_kernel_splice()
    print(f"Userspace copy: {u['mb_s']:.1f} MB/s, CPU: {u['cpu_s']*1000:.1f} ms")
    print(f"Kernel splice : {s['mb_s']:.1f} MB/s, CPU: {s['cpu_s']*1000:.1f} ms")
    print(f"Throughput improvement: +{(s['mb_s']/u['mb_s'] - 1)*100:.1f}%")
    print(f"CPU time reduction    : -{(1 - s['cpu_s']/u['cpu_s'])*100:.1f}%")
