def process_data(data):

    hr = data["heart_rate"]
    spo2 = data["spo2"]
    temp = data["temperature"]

    device = data["device_id"]

    print("Processing device:", device)

    if hr > 130:
        print("ALERT: High heart rate", hr)

    if spo2 < 90:
        print("ALERT: Low oxygen", spo2)

    if temp > 39:
        print("ALERT: High temperature", temp)