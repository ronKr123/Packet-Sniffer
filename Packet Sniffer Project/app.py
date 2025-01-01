from flask import Flask, jsonify, render_template
from scapy.all import sniff, IP, TCP

app = Flask(__name__, template_folder="templates")

# משתנה לשמירת הנתונים
captured_data = {"packets": [], "visited_urls": []}

# פונקציה לקליטת חבילות
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        captured_data["packets"].append({"src": src_ip, "dst": dst_ip})

        # בדיקה אם יש layer Raw עם http
        if packet.haslayer('Raw'):
            try:
                raw_data = packet['Raw'].load.decode(errors='ignore')
                # חיפוש אחרי כתובת URL מלאה
                if 'http' in raw_data.lower():
                    start_idx = raw_data.lower().find('http')
                    end_idx = raw_data.find(' ', start_idx)  # מחפש את הסימן רווח אחרי ה-URL
                    if end_idx != -1:
                        url = raw_data[start_idx:end_idx]
                    else:
                        url = raw_data[start_idx:]  # אם אין רווח, לוקחים את כל מה שנשאר
                    captured_data["visited_urls"].append(url)
                    captured_data["visited_urls"] = captured_data["visited_urls"][-5:]  # שומר רק 5 אחרונים
            except Exception as e:
                print(f"Error decoding raw data: {e}")


# הרצת Flask
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/data")
def data():
    return jsonify(captured_data)

if __name__ == "__main__":
    # הפעלת קליטה במקביל לשרת Flask
    import threading
    sniffer_thread = threading.Thread(target=lambda: sniff(prn=packet_callback, filter="ip", iface="Ethernet", count=0))
    sniffer_thread.daemon = True
    sniffer_thread.start()

    app.run(debug=True)
