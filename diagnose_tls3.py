import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

HOST = "127.0.0.1"

def connect_ex_only(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect_ex((HOST, port))
    finally:
        sock.close()

def banner_grab(i):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((HOST, 443), timeout=1.0) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=HOST) as tls_sock:
                tls_sock.settimeout(1.0)
                probe = f"HEAD / HTTP/1.1\r\nHost: {HOST}:443\r\nConnection: close\r\n\r\n".encode()
                tls_sock.sendall(probe)
                data = tls_sock.recv(1024)
                print(f"essai {i}: OK — {len(data)} octets")
    except Exception as e:
        print(f"essai {i}: ÉCHEC — {type(e).__name__}: {e}")

for i in range(1, 11):
    # Reproduit le scan de 189 ports avec 100 threads, comme dans le vrai test 2
    with ThreadPoolExecutor(max_workers=100) as executor:
        list(executor.map(connect_ex_only, range(443, 632)))
    # Immédiatement après, comme le fait main.py : récupération du banner
    banner_grab(i)
