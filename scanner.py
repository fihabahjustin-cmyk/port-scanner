import socket
import ssl
import errno
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sr1, send

DEFAULT_TIMEOUT = 1.0
NO_RESPONSE_ERRORS = {errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT}
TLS_PORTS = {443, 8443, 465, 993, 995, 636, 989, 990}


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise ValueError(f"Impossible de résoudre l'hôte '{host}' : {e}")


def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
    except socket.timeout:
        return "filtered"
    except OSError:
        return "error"
    finally:
        sock.close()
    if result == 0:
        return "open"
    if result == errno.ECONNREFUSED:
        return "closed"
    if result in NO_RESPONSE_ERRORS:
        return "filtered"
    if result in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        return "unreachable"
    return "closed"


def scan_range(host: str, start_port: int, end_port: int,
               timeout: float = DEFAULT_TIMEOUT, max_workers: int = 100) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(future_to_port):
            results[future_to_port[future]] = future.result()
    return results


def _http_probe(host: str, port: int) -> bytes:
    return (f"HEAD / HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Connection: close\r\n\r\n").encode()


def _read_banner_plain(host: str, port: int, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
        except socket.timeout:
            data = b""
        if not data:
            try:
                sock.sendall(_http_probe(host, port))
                data = sock.recv(1024)
            except (socket.timeout, OSError):
                data = b""
        return data


def _read_banner_tls(host: str, port: int, timeout: float) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.settimeout(timeout)
            tls_sock.sendall(_http_probe(host, port))
            try:
                return tls_sock.recv(1024)
            except socket.timeout:
                return b""


def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT, retries: int = 1):
    """
    Tente de récupérer un banner texte sur un port ouvert.
    Réessaie une fois en cas d'échec (connexion TLS/réseau parfois
    sensible à un aléa ponctuel de contention système), avant d'abandonner.
    Retourne la première ligne utile (str) ou None si rien d'exploitable.
    """
    for attempt in range(retries + 1):
        try:
            data = (_read_banner_tls(host, port, timeout) if port in TLS_PORTS
                    else _read_banner_plain(host, port, timeout))
        except Exception:
            data = None
        if data:
            text = data.decode("utf-8", errors="replace").strip()
            if text:
                return text.splitlines()[0][:120]
    return None


def scan_udp_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT, payload: bytes = b"\x00") -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.send(payload)
        try:
            sock.recv(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
    except OSError:
        return "error"
    finally:
        sock.close()


def scan_udp_range(host: str, start_port: int, end_port: int,
                    timeout: float = DEFAULT_TIMEOUT, max_workers: int = 50) -> dict:
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_udp_port, host, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(future_to_port):
            results[future_to_port[future]] = future.result()
    return results


def syn_scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> str:
    syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=timeout, verbose=0)
    if response is None:
        return "filtered"
    if response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:
            send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
            return "open"
        elif flags == 0x14:
            return "closed"
    return "filtered"


def syn_scan_range(host: str, start_port: int, end_port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    return {port: syn_scan_port(host, port, timeout)
            for port in range(start_port, end_port + 1)}
