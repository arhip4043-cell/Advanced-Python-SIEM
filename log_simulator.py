import json
import os
import time
import datetime import datetime

LOG_FILE= "logs_incoming/events.json"

def create_event(event_id, user_or_process):
  return{
    "event_id": event_id,
    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.000"),
    "data": ["", "", "", "", "", user_or_process]
  }

def simulate_attack():
  print("Inizio iniezione log...")
  os.makedirs("log_incoming", exist_ok=True)
  events=[]

  events.append(create_event(4625, "mario.rossi"))
  time.sleep(1)

  print("Lancio Brute Force su 'admin'...")
  for _ in range(5):
      events.append(create_event(4625, "admin"))

  print("Login riuscito per 'admin' (Compromissione!)...")
  events.append(create_event(4624, "admin"))

  print("[SIMULATORE] Esecuzione PowerShell da path sospetto...")
  events.append(create_event(4688, r"C:\Users\Public\Downloads\powershell.exe"))

  with open(LOG_FILE, "w") as f:
      json.dump(events, f, indent=2)

  print(f"Inviati {len(events)} eventi al SIEM.")

if __name__ == "__main__":
    simulate_attack()
