import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_TIMEOUT = 1.0  # secondes


def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """
    Tente une connexion TCP sur (host, port).
    Retourne True si le port répond (ouvert), False sinon.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()
def scan_range(host: str, start_port: int, end_port: int,
               timeout: float = DEFAULT_TIMEOUT, max_workers: int = 100) -> list[int]:
    """
    Scanne tous les ports de start_port à end_port (inclus) sur host, en parallèle.
    Retourne la liste triée des ports ouverts.
    """
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # On soumet une tâche de scan par port, et on garde une correspondance
        # future -> port, car as_completed() ne renvoie pas les résultats
        # dans l'ordre d'origine mais dans l'ordre où ils se terminent.
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)

    return sorted(open_ports)
