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
   - Se un utente genera l'Event ID `4625` (Login Fallito) molteplici volte, e successivamente genera l'Event ID `4624` (Login Riuscito), il sistema eleva automaticamente l'allarme a **CRITICAL**, segnalando una sospetta compromissione dell'account.

2. **Sliding Time Windows (Finestre Temporali):**
   - Gli attacchi Brute Force non vengono rilevati su un conteggio assoluto, ma all'interno di una finestra temporale specifica (es. 5 tentativi in 5 minuti). I tentativi più vecchi vengono scartati automaticamente, abbattendo drasticamente i Falsi Positivi.

3. **False Positive Reduction & Whitelisting:**
   - La detection dei processi (Event ID `4688`) monitora binari critici (es. `powershell.exe`). Tuttavia, per evitare l'alert fatigue, il motore controlla il `path` di esecuzione: se eseguito da directory legittime (es. `System32`), l'evento viene scartato. Viene flaggato solo da percorsi anomali.

---

## ⚙️ Architettura del Sistema

L'architettura è modulare e simula un ambiente Enterprise suddiviso in tre componenti:

```mermaid
graph TD
    subgraph Red Team / Attaccante
        A[log_simulator.py] -->|Inietta Log JSON| B(events.json)
    end

    subgraph SOC Detection Engine
        B -->|Legge Log Real-Time| C{detection.py}
        C -->|Sliding Window Check| D[Filtro Falsi Positivi]
        C -->|Stateful Analysis| E[Motore di Correlazione]
        D --> F[(alerts.json)]
        E --> F
    end

    subgraph Triage / Analyst View
        F -->|Fetch Dati| G[app.py - Flask Server]
        G -->|Render| H((Dashboard Web GUI))
    end

    classDef red fill:#5e1919,stroke:#ff0000,stroke-width:2px;
    classDef blue fill:#1a365d,stroke:#00a2ff,stroke-width:2px;
    classDef green fill:#124a2f,stroke:#00ff66,stroke-width:2px;
    
    class A red;
    class C,D,E blue;
    class H green;
````

* * *

## 📚 Documentazione Tecnica – Architettura dei Componenti e Data Flow SIEM

Per approfondire le logiche di analisi comportamentale e i flussi di risposta, consulta la documentazione dettagliata:

-   🔗 [Diagrammi di Sequenza e Timeline degli Attacchi](docs/DETECTION_LOGIC.md)
    
-   🔗 [Analisi dell'Albero dei Processi Malware (LOLBins)](docs/DETECTION_LOGIC.md)
    
-   🔗 [Workflow Operativo SOC (Incident Response)](docs/DETECTION_LOGIC.md)
    

* * *

## 🛡️ Mappatura MITRE ATT&CK®

Il Detection Engine è stato mappato sul framework globale MITRE per garantire la copertura delle tattiche più comuni:

| Tactic | Technique ID | Technique Name | Detection Logic nel SIEM | Severity |
| --- | --- | --- | --- | --- |
| 🔑 **Credential Access** | T1110 | Brute Force | Monitoraggio soglie Event ID 4625 (Sliding Window 5 min) | 🟠 HIGH |
| 🔓 **Initial Access** | T1078 | Valid Accounts | Correlazione 4625 -> 4624 (Tentativi falliti seguiti da successo) | 🔴 CRIT |
| ⚙️ **Execution** | T1059.001 | PowerShell | Event ID 4688 + Regex su parametri (es. \\-enc) | 🔴 CRIT |
| 🥷 **Defense Evasion** | T1036 | Masquerading | Analisi Path di esecuzione vs LOLBins (Whitelisting System32) | 🟡 MED |

* * *

## 🚀 Come testare la Demo (Guida all'uso)

**1\. Avvia il Motore SIEM:**

```bash
python main.py
```

**2\. Avvia la Dashboard (Analista SOC):** Apri il browser su http://127.0.0.1:5000.

```bash
python app.py
```

**3\. Lancia l'attacco simulato (Red Team):**

```bash
python log_simulator.py
```

* * *

## 📸 Screenshot della Dashboard

(Spazio per la foto della Dashboard di Flask)

* * *

Progetto realizzato per dimostrare competenze pratiche in ambito Log Analysis, SIEM Architecture e Incident Detection.

