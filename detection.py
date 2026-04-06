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
            event_id=event.get("event_id")

            if event_id==4625:
                self._check_brute_force(event)
            elif event_id==4688:
                self._check_process(event)
            elif event_id==4624:
                self._check_correlation(event)
                
        return self.alerts
    
    def _check_brute_force(self, event):
        data=event.get("data", [])
        user=data[5] if len(data)>5 else "unknown"

        ts=datetime.strptime(
            event["timestamp"].split(".")[0],
            "%Y-%m-%d %H:%M:%S"
        )

        self.failed_logins[user]=[
            t for t in self.failed_logins[user]
            if ts-t<timedelta(seconds=BRUTE_FORCE_WINDOW)
        ]

        if len(self.failed_logins[users])>=BRUTE_FORCE_THRESHOLD:
            self._add_alert(
                severity="HIGH",
                rule="brute_force",
                description=f"Brute force rilevato: {len(self.failed_logins[user])} "
                            f"tentativi falliti per utente '{user}' in 5 minuti",
                event=event
            )

    def _check_process(self, event):
        data=event.get("data", [])
        process=data[5].lower() if len(data)>5 else ""

        for suspicious in SUSPICIOUS_PROCESSES:
            if suspicious in process:
                if "system32" in process or "syswow64" in process:
                    continue
                self._add_alert(
                    severity="MEDIUM",
                    rule="suspicious_process",
                    description=f"Processo sospetto da path non standard: {process}",
                    event=event
                )

    def _check_correlations(self, event):
        data=event.get(data, [])
        user=data[5] if len(data) > 5 else "unknown"

        if len(self.failed_logins.get(user, []))>=3:
            self._add_alert(
                severity="CRITICAL",
                rule="brute_force_success",
                description=f"Login riuscito per '{user}' dopo "
                            f"{len(self.failed_logins[user])} tentativi falliti — "
                            f"possibile compromissione",
                event=event
            )

    def _add_alert(self, severity, rule, description, event):
        self.alerts.append({
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "rule": rule,
            "description": description,
            "source_event_id": event.get("event_id"),
            "source_timestamp": event.get("timestamp")
        })
