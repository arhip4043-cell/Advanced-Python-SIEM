from datetime import datetime, timedelta
from collections import defaultdict


BRUTE_FORCE_THRESHOLD=5;
BRUTE_FORCE_WINDOW=300; 
SOUSPICIOUS_PROCESS=[
    "powershell.exe",
    "wscript.exe",
    "mshta.exe",
    "regsvr32.exe"
]

class DetectionEngine:
    def __init__(self):
        self.failed_logins=defaultdict(list)
        self.alerts=[]

    def analyze(self, events):
        for event in events:
            self._check_brute_force(event)
            self._check_process(event)
            self._check_correlation(event)
        return self.alerts
    
    def _check_brute_force(self, event):
        if event ["event_id"]!= 4625:
            return
        
        user=event["data"][5] if len(event["data"])>5 else "unknown"
        ts=datetime.strptime(
            event["timestamp"].split(".")[0],
            "%Y-%m-%d %H:%M:%S"
        )

        self.failed_logins[user]=[
            t for t in self.failed_logins[user]
            if ts-t<timedelta(seconds=BRUTE_FORCE_WINDOW)
        ]
        self.failed_logins[user].append(ts)

        if len(self.failed_logins[user])>=BRUTE_FORCE_THRESHOLD:
            self._add_alert(
                severity="ALTO",
                rule="Brute Force",
                description=f"Brute force rilevato: {len(self.failed_logins[user])}"
                f"tentativi falliti per utente '{user}' in 5 muinuti",
                event=event
            )
    def _check_correlation(self, event):
        if event["event_id"]!=4624:
            return
        
        user=event["data"][5] if len(event["data"])>5 else "unknown"
        if len(self.failed_logins.get(user, []))>=3:
            self._add_alert(
                severity="CRITICO",
                rule="brute_force_success",
                description=f"Login riuscito per '{user}' dopo"
                            f"{len(self.failed_logins[user])} tentativi falliti-"
                            f"possibile compromissione",
                            event=event
            )
    def _add_alert(self, severity, rule, description, event):
        self.alerts.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "rule": rule,
            "description": description,
            "source_event_id": event["event_id"],
            "source_timestamp": event["timestamp"]
        })
        
