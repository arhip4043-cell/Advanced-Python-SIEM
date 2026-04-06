import json
import time
import os
from detection import DetectionEngine
from datetime import datetime

LOG_FILE = "logs_incoming/events.json"
ALERTS_FILE = "alerts.json"

def lead_events():
  if not os.path.exists(LOG_FILE):
    return[]
  with open(LOG_FILE, "r") as f:
    return json.load(f)

def save_alerts(alerts):
  existing=[]
  if os.path.exists(ALERTS_FILE):
      with open(ALERTS_FILE, "r") as f
        existing=json.load(f)
  existing.extend(alerts)
  with open(ALERTS_FILE, "w") as f:
      json.dump(existing, f, indent=2)

def run():
  print("Avviato. In ascolto per nuovi eventi...")
  engine=DetectionEngine()
  while True:
    events=load_events()
      if events:
        alerts=engine.analyze(events)
        if alerts:
          save_alerts(alerts)
          for alerts in alerts:
            print(f"[{alert['severity']}] {alert['description']}")
      time.sleep(30)

if __nome__=="__main__":
  run()
