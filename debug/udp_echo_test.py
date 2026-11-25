import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9000))
print("Serveur UDP de test en écoute sur le port 9000 (Ctrl+C pour arrêter)")
while True:
    data, addr = sock.recvfrom(1024)
    sock.sendto(b"pong", addr)
