import argparse
import socket
import time

from scanner import scan_range, scan_udp_range, syn_scan_range, resolve_host, grab_banner


def parse_port_range(value: str):
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


def build_parser():
    parser = argparse.ArgumentParser(
        description="Scanner de ports TCP/UDP simple (usage pédagogique, cibles autorisées uniquement)."
    )
    parser.add_argument("host", help="Adresse ou nom d'hôte de la cible (ex: 127.0.0.1)")
    parser.add_argument("-p", "--ports", type=parse_port_range, default=(1, 1024),
                         help="Plage de ports, ex: 1-1000 ou 80 (défaut: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                         help="Timeout par port en secondes (défaut: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                         help="Threads simultanés (défaut: 100)")
    parser.add_argument("--no-banner", action="store_true",
                         help="Désactive la récupération de banner (TCP uniquement)")
    parser.add_argument("-u", "--udp", action="store_true",
                         help="Scan UDP au lieu de TCP")
    parser.add_argument("-s", "--syn", action="store_true",
                         help="Scan SYN furtif (nécessite sudo)")
    return parser


def run_tcp_scan(args, ip):
    debut = time.time()
    results = scan_range(ip, *args.ports, timeout=args.timeout, max_workers=args.workers)
    duree = time.time() - debut

    open_ports = sorted(p for p, s in results.items() if s == "open")
    closed_ports = sorted(p for p, s in results.items() if s == "closed")
    filtered_ports = sorted(p for p, s in results.items() if s == "filtered")
    unreachable_ports = sorted(p for p, s in results.items() if s == "unreachable")
    error_ports = sorted(p for p, s in results.items() if s == "error")

    print(f"\nTerminé en {duree:.2f}s sur {len(results)} port(s) scanné(s) :")
    print(f"  {len(open_ports)} ouvert(s), {len(closed_ports)} fermé(s), "
          f"{len(filtered_ports)} filtré(s), {len(unreachable_ports)} injoignable(s), "
          f"{len(error_ports)} erreur(s)\n")

    if not open_ports:
        print("  (aucun port ouvert)")
    for port in open_ports:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "inconnu"
        line = f"  {port}/tcp\topen\t{service}"
        if not args.no_banner:
            banner = grab_banner(ip, port, timeout=args.timeout)
            if banner:
                line += f"\t| {banner}"
        print(line)


def run_udp_scan(args, ip):
    debut = time.time()
    results = scan_udp_range(ip, *args.ports, timeout=args.timeout, max_workers=args.workers)
    duree = time.time() - debut

    open_ports = sorted(p for p, s in results.items() if s == "open")
    closed_ports = sorted(p for p, s in results.items() if s == "closed")
    ambiguous_ports = sorted(p for p, s in results.items() if s == "open|filtered")
    error_ports = sorted(p for p, s in results.items() if s == "error")

    print(f"\nTerminé en {duree:.2f}s sur {len(results)} port(s) UDP scanné(s) :")
    print(f"  {len(open_ports)} ouvert(s), {len(closed_ports)} fermé(s), "
          f"{len(ambiguous_ports)} ouvert|filtré(s) (ambigu), {len(error_ports)} erreur(s)\n")

    for port in open_ports:
        print(f"  {port}/udp\topen")
    for port in ambiguous_ports:
        print(f"  {port}/udp\topen|filtered")


def run_syn_scan(args, ip):
    debut = time.time()
    results = syn_scan_range(ip, *args.ports, timeout=args.timeout)
    duree = time.time() - debut

    open_ports = sorted(p for p, s in results.items() if s == "open")
    closed_ports = sorted(p for p, s in results.items() if s == "closed")
    filtered_ports = sorted(p for p, s in results.items() if s == "filtered")

    print(f"\nTerminé en {duree:.2f}s sur {len(results)} port(s) scanné(s) (SYN) :")
    print(f"  {len(open_ports)} ouvert(s), {len(closed_ports)} fermé(s), "
          f"{len(filtered_ports)} filtré(s)\n")
    for port in open_ports:
        print(f"  {port}/tcp\topen (SYN)")


def main():
    args = build_parser().parse_args()
    try:
        ip = resolve_host(args.host)
    except ValueError as e:
        print(f"Erreur : {e}")
        return

    cible = args.host if args.host == ip else f"{args.host} ({ip})"
    start, end = args.ports
    mode = "SYN" if args.syn else ("UDP" if args.udp else "TCP")
    print(f"Scan {mode} de {cible} sur les ports {start}-{end} "
          f"(timeout={args.timeout}s, workers={args.workers})...")

    try:
        if args.syn:
            run_syn_scan(args, ip)
        elif args.udp:
            run_udp_scan(args, ip)
        else:
            run_tcp_scan(args, ip)
    except PermissionError:
        print("Erreur : le scan SYN nécessite les privilèges root. Relance avec sudo.")


if __name__ == "__main__":
    main()
