## 🚀 Prossimi Sviluppi: Threat Intelligence & Mobile SOC (Endpoint Focus)

Per elevare ulteriormente le capacità di rilevamento del SIEM e avvicinarlo alle logiche operative di un vero e proprio **motore Anti-Malware**, le prossime versioni prevedranno l'introduzione di analisi comportamentale basata su firme (IoC) e l’estensione del monitoraggio ai dispositivi Mobile.

1.  **Malware Detection & Threat Intelligence (IoC Matching):**
    
    -   Il motore sarà in grado di processare log di esecuzione avanzati (simulando _Sysmon Event ID 1_), estraendo l'**Hash (SHA-256)** e il nome originale dei binari eseguiti.
    -   È prevista l’implementazione di un controllo in tempo reale contro un database di **IoC (Indicators of Compromise)**. In caso di rilevamento dell’esecuzione di file noti per attività malevole (es. _mimikatz.exe_) o con firme digitali sospette, il sistema genererà alert **CRITICAL** di tipo _Malware Signature_, con capacità di risposta a livello di Endpoint.
2.  **Mobile SOC (Analisi Log Android™):**
    
    -   Sarà introdotto un ingestore dedicato per il parsing degli eventi di sistema Android (simulando flussi `adb logcat`).
    -   Il SIEM potrà rilevare minacce specifiche per il mondo mobile, tra cui:
        
        -   **Sideloading:** Installazione di pacchetti APK da sorgenti non attendibili o di terze parti.
        -   **Privilege Escalation:** Comportamenti anomali volti all’ottenimento illecito dei permessi di _Root_ (esecuzione di binari `su`).

---

## 🛡️ Mappatura MITRE ATT&CK® (Aggiornata alla versione 2)

Il Detection Engine sarà mappato sul framework globale MITRE (Enterprise & Mobile) per garantire la copertura delle tattiche più comuni:

| Tactic | Technique ID | Technique Name | Detection Logic nel SIEM | Severity |
| :--- | :---: | :--- | :--- | :---: |
| 🔑 **Credential Access** | `T1110` | Brute Force | Monitoraggio soglie *Event ID 4625* (Sliding Window 5 min) | 🟠 HIGH |
| 🔓 **Initial Access** | `T1078` | Valid Accounts | Correlazione *4625 -> 4624* (Tentativi falliti seguiti da successo) | 🔴 CRIT |
| ⚙️ **Execution** | `T1059.001` | PowerShell | *Event ID 4688* + Regex su parametri (es. `-enc`) | 🔴 CRIT |
| 🥷 **Defense Evasion** | `T1036` | Masquerading | Analisi Path di esecuzione vs LOLBins (Whitelisting System32) | 🟡 MED |
| 🦠 **Malware / Cred. Access**| `T1003` | OS Credential Dumping | IoC Matching: Rilevamento Hash/Nome di *Mimikatz* (Sysmon log) | 🔴 CRIT |
| 📱 **Mobile: Initial Access**| `T1414` | App Installation | Parsing log Android per installazione APK fuori dal Play Store | 🟠 HIGH |
