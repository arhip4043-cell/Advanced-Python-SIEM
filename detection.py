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
    
