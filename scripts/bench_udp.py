#!/usr/bin/env python3
"""
Benchmark comparing 1-by-1 UDP packet syscalls vs batched recvmmsg.
"""
import ctypes
import os
import socket
import time
import threading

libc = ctypes.CDLL("libc.so.6", use_errno=True)

class Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

class Msghdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint32),
        ("msg_iov", ctypes.POINTER(Iovec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int),
    ]

class Mmsghdr(ctypes.Structure):
    _fields_ = [
        ("msg_hdr", Msghdr),
        ("msg_len", ctypes.c_uint32),
    ]

BATCH_SIZE = 32
NUM_PACKETS = 50000

def test_single_packet_udp():
    s_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_rx.bind(("127.0.0.1", 0))
    port = s_rx.getsockname()[1]
    s_rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)
    
    def sender():
        s_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"U" * 256
        for _ in range(NUM_PACKETS):
            s_tx.sendto(payload, ("127.0.0.1", port))
        s_tx.close()

    t = threading.Thread(target=sender)
    
    t0 = time.process_time()
    wall0 = time.perf_counter()
    t.start()
    
    import select
    
    received = 0
    s_rx.setblocking(False)
    while received < NUM_PACKETS:
        r, _, _ = select.select([s_rx], [], [], 0.5)
        if not r:
            break
        try:
            data, _ = s_rx.recvfrom(2048)
            received += 1
        except BlockingIOError:
            continue
            
    wall1 = time.perf_counter()
    cpu1 = time.process_time()
    t.join()
    s_rx.close()
    return {"wall_s": wall1 - wall0, "cpu_s": cpu1 - t0, "pps": received / (wall1 - wall0)}

def test_batched_udp():
    s_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_rx.bind(("127.0.0.1", 0))
    port = s_rx.getsockname()[1]
    s_rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)
    
    buffers = [ctypes.create_string_buffer(2048) for _ in range(BATCH_SIZE)]
    iovecs = (Iovec * BATCH_SIZE)()
    for i in range(BATCH_SIZE):
        iovecs[i].iov_base = ctypes.cast(buffers[i], ctypes.c_void_p)
        iovecs[i].iov_len = 2048
        
    mmsg = (Mmsghdr * BATCH_SIZE)()
    for i in range(BATCH_SIZE):
        mmsg[i].msg_hdr.msg_iov = ctypes.pointer(iovecs[i])
        mmsg[i].msg_hdr.msg_iovlen = 1
        
    recvmmsg_fn = libc.recvmmsg
    recvmmsg_fn.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(Mmsghdr),
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    recvmmsg_fn.restype = ctypes.c_int

    def sender():
        s_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"U" * 256
        for _ in range(NUM_PACKETS):
            s_tx.sendto(payload, ("127.0.0.1", port))
        s_tx.close()

    t = threading.Thread(target=sender)

    t0 = time.process_time()
    wall0 = time.perf_counter()
    t.start()

    import select
    
    received = 0
    fd = s_rx.fileno()
    s_rx.setblocking(False)
    while received < NUM_PACKETS:
        r, _, _ = select.select([s_rx], [], [], 0.5)
        if not r:
            break
        n = recvmmsg_fn(fd, mmsg, BATCH_SIZE, 0x40, None) # MSG_DONTWAIT = 0x40
        if n > 0:
            received += n
        else:
            err = ctypes.get_errno()
            if err in (11, 4): # EAGAIN / EINTR
                continue
            break
            
    wall1 = time.perf_counter()
    cpu1 = time.process_time()
    t.join()
    s_rx.close()
    return {"wall_s": wall1 - wall0, "cpu_s": cpu1 - t0, "pps": received / (wall1 - wall0)}

if __name__ == "__main__":
    s1 = test_single_packet_udp()
    sb = test_batched_udp()
    print(f"1-packet recvfrom: {s1['pps']:.0f} pps, CPU: {s1['cpu_s']*1000:.1f} ms")
    print(f"Batched recvmmsg : {sb['pps']:.0f} pps, CPU: {sb['cpu_s']*1000:.1f} ms")
    print(f"Throughput boost : +{(sb['pps']/s1['pps'] - 1)*100:.1f}%")
    print(f"CPU time savings : -{(1 - sb['cpu_s']/s1['cpu_s'])*100:.1f}%")
