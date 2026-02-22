#!/usr/bin/env python3

import queue, time
import pe.app

class UIMonitor(pe.monitor.Monitor):
    def __init__(self):
        self.queue = queue.Queue()

    def monitored_unproto(self, port, call_from, call_to, text, data):
        self.queue.put({
            "from": call_from,
            "to": call_to,
            "text": text,
            "data": data,
        })

AGW_HOST = '127.0.0.1'
AGW_PORT = 8000
AX25_PORT = 0
FROM_CALL = "N0CALL"
TO_CALL = "QST"
MSG = b"Hello\x00world"
VIA = []  


app = pe.app.Application()
monitor = UIMonitor()
app.use_monitor(monitor)
app.start(AGW_HOST, AGW_PORT)
app.enable_monitoring = True
print(f"length of string: {str(len(MSG))}")
print(MSG.decode('utf-8', errors='replace'))
app.send_unproto(
    AX25_PORT,
    FROM_CALL,
    TO_CALL,
    MSG,
    VIA,
)

stop_counter = 0
while stop_counter<100:
    while not monitor.queue.empty():
        queue_item = monitor.queue.get()
        data_item = queue_item["data"]
        print(f"length of string: {str(len(data_item))}")
        print(data_item.decode('utf-8', errors='replace'))
    stop_counter +=1
    time.sleep(0.05)

print("stopping monitor")
app.enable_monitoring = False
app.stop()

