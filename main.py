import argparse
import socket
import time

from scanner import scan_range


def parse_port_range(value: str) -> tuple[int, int]:
    """Convertit '1-1000' ou '80' en (start, end)."""
    if "-" in value:
        start_str, end_str = value.split("-", 1)
        start, end = int(start_str), int(end_str)
    else:
        start = end = int(value)

    if not (0 < start <= end <= 65535):
        raise argparse.ArgumentTypeError(
            f"Plage de ports invalide : '{value}' (attendu entre 1 et 65535, start <= end)"
        )
    return start, end


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP simple (usage pédagogique, cibles autorisées uniquement)."
    )
    parser.add_argument("host", help="Adresse ou nom d'hôte de la cible (ex: 127.0.0.1)")
    parser.add_argument(
        "-p", "--ports", type=parse_port_range, default=(1, 1024),
        help="Plage de ports, ex: 1-1000 ou 80 (défaut: 1-1024)"
    )
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                         help="Timeout par port en secondes (défaut: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                         help="Threads simultanés (défaut: 100)")
    return parser


def main():
    args = build_parser().parse_args()
    start, end = args.ports

    print(f"Scan de {args.host} sur les ports {start}-{end} "
          f"(timeout={args.timeout}s, workers={args.workers})...")

    debut = time.time()
    open_ports = scan_range(args.host, start, end, timeout=args.timeout, max_workers=args.workers)
    duree = time.time() - debut

    print(f"\nTerminé en {duree:.2f}s — {len(open_ports)} port(s) ouvert(s) :\n")
    if not open_ports:
        print("  (aucun)")
    for port in open_ports:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "inconnu"
        print(f"  {port}/tcp\topen\t{service}")


if __name__ == "__main__":
    main()
