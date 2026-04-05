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
