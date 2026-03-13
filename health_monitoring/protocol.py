import struct
import time

VERSION = 1
MSG_TELEMETRY = 3

def encode_packet(device_id, heart_rate, spo2, temp):
    seq = int(time.time()) % 65535
    timestamp = int(time.time())

    payload = struct.pack("!BBH",
        heart_rate,
        spo2,
        int(temp * 100)
    )

    header = struct.pack(
        "!BBIHI",
        VERSION,
        MSG_TELEMETRY,
        device_id,
        seq,
        timestamp
    )

    return header + payload


def decode_packet(data):

    header_size = struct.calcsize("!BBIHI")

    version, msg_type, device_id, seq, timestamp = struct.unpack(
        "!BBIHI", data[:header_size]
    )

    heart_rate, spo2, temp = struct.unpack("!BBH", data[header_size:])

    temp = temp / 100

    return {
        "version": version,
        "type": msg_type,
        "device_id": device_id,
        "sequence": seq,
        "timestamp": timestamp,
        "heart_rate": heart_rate,
        "spo2": spo2,
        "temperature": temp
    }