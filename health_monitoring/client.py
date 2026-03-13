import socket
import random
import time
from protocol import encode_packet

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9000

device_id = random.randint(1000,9999)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Client started:", device_id)

while True:

    heart_rate = random.randint(60,120)
    spo2 = random.randint(94,100)
    temp = round(random.uniform(36.0,37.5),2)

    packet = encode_packet(device_id, heart_rate, spo2, temp)

    sock.sendto(packet,(SERVER_IP,SERVER_PORT))

    print("Sent:", heart_rate, spo2, temp)

    time.sleep(2)