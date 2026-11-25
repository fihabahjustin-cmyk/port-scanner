import socket
import ssl
import time

HOST, PORT = "127.0.0.1", 443

def status_check():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect_ex((HOST, PORT))
    finally:
        sock.close()

def banner_grab(i):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((HOST, PORT), timeout=1.0) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=HOST) as tls_sock:
                tls_sock.settimeout(1.0)
                probe = f"HEAD / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n\r\n".encode()
                tls_sock.sendall(probe)
                data = tls_sock.recv(1024)
                print(f"essai {i}: OK — {len(data)} octets")
    except Exception as e:
        print(f"essai {i}: ÉCHEC — {type(e).__name__}: {e}")

for i in range(1, 21):
    status_check()          # reproduit exactement scan_port()
    banner_grab(i)           # reproduit exactement grab_banner(), juste après
