import socket
from protocol import decode_packet
from processor import process_data

HOST = "0.0.0.0"
PORT = 9000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST,PORT))

print("UDP Gateway listening on port", PORT)

while True:

    data, addr = sock.recvfrom(1024)

    telemetry = decode_packet(data)

    print("Received from", addr, telemetry)

    process_data(telemetry)