# 🛡️ Advanced Python SIEM: Threat Detection & Correlation Engine

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Web_Dashboard-green.svg)
![CyberSecurity](https://img.shields.io/badge/Role-SOC_Analyst_Portfolio-darkred.svg)

## 🎯 Panoramica del Progetto
Questo progetto è un **Mini-SIEM (Security Information and Event Management)** sviluppato in Python. A differenza dei classici parser di log, questo sistema non si limita a leggere righe di testo, ma implementa un vero e proprio **motore di correlazione (Stateful Detection)** e logiche di analisi basate su **finestre temporali (Sliding Windows)**.

Il progetto è stato sviluppato per dimostrare competenze pratiche operative tipiche di un **SOC Analyst (L1/L2)**, passando dalla pura teoria all'implementazione tecnica delle regole di rilevamento.

---

## 🧠 Core Features & Logica di Detection

Questo SIEM supera i rilevamenti statici implementando tre concetti chiave delle Security Operations:

1. **Stateful Event Correlation (Correlazione di Stato):**
   - Il sistema mantiene in memoria lo storico delle azioni degli utenti (`defaultdict`). 
   - Se un utente genera l'Event ID `4625` (Login Fallito) molteplici volte, e successivamente genera l'Event ID `4624` (Login Riuscito), il sistema eleva automaticamente l'allarme a **CRITICAL**, segnalando una sospetta compromissione dell'account (Brute Force andato a buon fine).

2. **Sliding Time Windows (Finestre Temporali):**
   - Gli attacchi Brute Force non vengono rilevati su un conteggio assoluto, ma all'interno di una finestra temporale specifica (es. 5 tentativi in 5 minuti). I tentativi più vecchi vengono scartati automaticamente, abbattendo drasticamente i Falsi Positivi causati da utenti sbadati durante la giornata.

3. **False Positive Reduction & Whitelisting:**
   - La detection dei processi sospetti (Event ID `4688`) monitora binari critici (es. `powershell.exe`). Tuttavia, per evitare l'alert fatigue, il motore controlla il `path` di esecuzione: se PowerShell viene eseguito dalle directory legittime (es. `System32`), l'evento viene scartato. Viene flaggato solo se eseguito da percorsi anomali (es. `C:\Users\Public\`).

---

## ⚙️ Architettura del Sistema

L'architettura è modulare e simula un ambiente Enterprise suddiviso in tre componenti:

```text
[ log_simulator.py ] ---> (events.json) ---> [ main.py + detection.py ] ---> (alerts.json) ---> [ app.py (Flask) ]
   (Generatore)           (Log Ingress)         (Motore di Analisi)           (DB Allarmi)        (Dashboard SOC)
```

1. **Il Simulatore:** Inietta log JSON formattati per simulare il rumore di fondo e attacchi mirati.
2. **Il Detection Engine:** Un demone sempre in ascolto che analizza i log, applica le regole matematiche e temporali, e genera gli allarmi.
3. **La Dashboard Web:** Un'interfaccia grafica per il triage in tempo reale con livelli di severità (`MEDIUM`, `HIGH`, `CRITICAL`).

---

## 🚀 Come testare la Demo (Guida all'uso)

Per vedere il SIEM in azione (e le regole di correlazione), è necessario aprire 3 terminali separati.

**1. Avvia il Motore SIEM:**
Questo avvierà il demone che ascolta i nuovi eventi in entrata.
```bash
python main.py
```

**2. Avvia la Dashboard (Analista SOC):**
Questo avvierà l'interfaccia web. Apri il browser su `http://127.0.0.1:5000`.
```bash
python app.py
```

**3. Lancia l'attacco simulato (Red Team):**
Questo script inietterà rumore di fondo, un attacco brute force, una compromissione correlata e l'esecuzione di un malware.
```bash
python log_simulator.py
```
*Immediatamente, osserverai la Dashboard web aggiornarsi automaticamente mostrando il triage degli attacchi.*

---

## 📸 Screenshot della Dashboard
*(Spazio per la foto)*

---

## 🛡️ Mappatura MITRE ATT&CK®

Le regole di detection attuali coprono le seguenti tecniche:
- **T1110 (Brute Force):** Rilevamento tramite monitoraggio soglie Event ID 4625.
- **T1078 (Valid Accounts):** Rilevamento tramite correlazione 4625 -> 4624.
- **T1059.001 (PowerShell):** Monitoraggio Event ID 4688 associato a percorsi di esecuzione sospetti.

---
*Progetto realizzato per dimostrare competenze pratiche in ambito Log Analysis, SIEM Architecture e Incident Detection.*
