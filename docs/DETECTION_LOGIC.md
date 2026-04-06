# 🧠 Logiche di Analisi Tecniche del Programma

Questo documento approfondisce le regole di correlazione implementate nel motore del SIEM e illustra come il sistema si integra nei processi operativi di un Security Operations Center (SOC) e nell'Incident Response.

---

## 1. Correlazione degli Eventi: Compromissione (Brute Force Success)

Il motore non si limita al conteggio statico, ma valuta le azioni nel tempo sfruttando la **Stateful Detection**. Il seguente diagramma illustra come il SIEM correla eventi separati nel tempo per confermare un'intrusione reale, scartando i tentativi isolati.

```mermaid
sequenceDiagram
    participant Utente as Attaccante
    participant Windows as Event Log
    participant SIEM as Detection Engine
    participant Dashboard as SOC Analyst

    Utente->>Windows: Sbaglia Password (x4)
    Windows-->>SIEM: Invia Event ID 4625
    SIEM->>SIEM: Salva in memoria (Timestamp)
    SIEM-->>Dashboard: Nessun Alert (Sotto soglia temporale)
    
    Utente->>Windows: Sbaglia Password (5° volta)
    Windows-->>SIEM: Invia Event ID 4625
    SIEM->>Dashboard: Genera Alert HIGH (Brute Force Detected)
    
    Utente->>Windows: Indovina Password!
    Windows-->>SIEM: Invia Event ID 4624 (Login Riuscito)
    SIEM->>SIEM: Cerca storico utente negli ultimi 5 min
    SIEM->>Dashboard: 🚨 Genera Alert CRITICAL (Compromissione Confermata)
```

---

## 2. Analisi dell'Albero dei Processi (Malware & LOLBins)

Per rilevare minacce avanzate che non usano eseguibili malevoli noti (sfruttando binari di sistema legittimi - *Living Off The Land*), il SIEM effettua un'analisi comportamentale. Il motore analizza la catena di esecuzione (*Process Lineage*) e verifica i percorsi di origine per abbattere i falsi positivi.

```mermaid
graph TD
    subgraph "Utente Ingannato"
        A[outlook.exe] -->|Apre allegato| B[Fattura_Scaduta.doc]
    end

    subgraph "Esecuzione Nascosta - Invisibile all'utente"
        B -->|Esegue Macro VBA| C{winword.exe}
        C -->|Genera processo figlio| D[cmd.exe]
        D -->|Bypass Execution Policy| E[powershell.exe -enc ZWNoby...]
    end

    subgraph "Azione Malevola"
        E -->|Download Payload| F((Malware.exe))
        E -->|Modifica Registro| G[(Chiave Run - Persistenza)]
    end

    classDef normal fill:#1a365d,stroke:#00a2ff,stroke-width:2px;
    classDef warning fill:#5c4000,stroke:#ffaa00,stroke-width:2px;
    classDef critical fill:#5e1919,stroke:#ff0000,stroke-width:2px;

    class A,B normal;
    class C,D warning;
    class E,F,G critical;
```

---

## 3. Timeline dell'Attacco e Triage (Kill Chain)

Rappresentazione cronologica della catena di attacco (simulata tramite `log_simulator.py`) e il relativo tempo di reazione del SIEM nella generazione degli alert per l'analista.

```mermaid
gantt
    title Attack Lifecycle & SIEM Detection Response
    dateFormat  HH:mm:ss
    axisFormat  %H:%M:%S

    section Recon & Access
    Rumore di fondo (Login fallito singolo) :done, 10:00:00, 1s
    Brute Force Attack (5 tentativi)       :done, 10:05:00, 5s
    Login Riuscito (Compromissione)        :crit, 10:05:05, 2s

    section Execution
    Ricognizione interna (whoami)          :10:06:00, 3s
    Esecuzione PowerShell Sospetto         :crit, 10:06:15, 5s

    section SIEM Response
    Triage Alert (HIGH) - Brute Force      :milestone, 10:05:05, 0s
    Triage Alert (CRITICAL) - Compromise   :milestone, 10:05:07, 0s
    Triage Alert (CRITICAL) - LOLBin Use   :milestone, 10:06:16, 0s
```

---

## 4. Integrazione Operativa: SOC Playbook

Il sistema è stato progettato tenendo a mente il lavoro dell'analista, automatizzando la scrematura del rumore di fondo per permettere al Livello 1 (L1) di concentrarsi sul triage delle vere minacce. Questo diagramma mostra come il tool si inserisce nel flusso di risposta agli incidenti.

```mermaid
stateDiagram-v2
    [*] --> Evento_Windows: Generazione Log
    Evento_Windows --> Detection_Engine: Parsing & Normalizzazione

    state Detection_Engine {
        [*] --> Analisi_Statica
        Analisi_Statica --> Correlazione_Temporale
        Correlazione_Temporale --> Whitelisting_Check
    }

    Detection_Engine --> Alert_Generato: Condizioni soddisfatte
    Detection_Engine --> Scartato: Falso Positivo / Rumore

    Alert_Generato --> Analista_L1: Triage in Dashboard Web

    state Analista_L1 {
        Valutazione_Severità_e_IoC
    }

    Analista_L1 --> Chiusura_Ticket: Falso Allarme (False Positive)
    Analista_L1 --> Escalation_L2: Conferma Minaccia (True Positive)

    Escalation_L2 --> Contenimento: Es. Isolamento Host da Rete
    Contenimento --> Eradicazione: Es. Rimozione Malware / Reset Pass
    Eradicazione --> [*]: Report d'Incidente al Cliente
```
