from typing import Dict

EXPLAINERS: Dict[str, Dict[str, str]] = {
    'Brute Force': {
        'danger_level': 'Alto',
        'explanation_it': "L'attaccante sta tentando molte combinazioni di credenziali sul servizio esposto, con l'obiettivo di ottenere accesso non autorizzato.",
        'advice': 'Abilita chiavi SSH o MFA, imposta rate limit o fail2ban e disattiva credenziali deboli o di default.',
    },
    'SQL Injection': {
        'danger_level': 'Alto',
        'explanation_it': 'Il payload contiene pattern tipici di manipolazione di query SQL per leggere, alterare o estrarre dati dal database.',
        'advice': 'Usa query parametrizzate, valida gli input e registra i tentativi sulle route sensibili.',
    },
    'XSS Attack': {
        'danger_level': 'Medio',
        'explanation_it': 'Il payload prova a iniettare JavaScript o attributi HTML attivi per eseguire codice nel browser della vittima.',
        'advice': "Esegui escaping dell'output, applica Content Security Policy e sanitizza ogni input utente.",
    },
    'Command Injection': {
        'danger_level': 'Alto',
        'explanation_it': "L'attaccante sta tentando di far eseguire comandi di sistema al servizio, spesso per scaricare payload o aprire una shell.",
        'advice': 'Non concatenare input utente in comandi shell, limita i privilegi del processo e monitora wget, curl, bash o sh sospetti.',
    },
    'Malware Upload': {
        'danger_level': 'Alto',
        'explanation_it': "L'evento indica il trasferimento o il download di un payload malevolo destinato a compromettere il sistema o a propagarsi.",
        'advice': "Blocca upload non necessari, isola il servizio, controlla IOC e conserva i campioni in un'area sicura per analisi.",
    },
    'SMB Attack': {
        'danger_level': 'Alto',
        'explanation_it': "L'attivita punta al protocollo SMB, spesso usato per enumerazione, exploit di condivisioni di rete o movimento laterale.",
        'advice': 'Disabilita versioni obsolete di SMB, limita la porta 445 e applica patch di sicurezza tempestive.',
    },
    'FTP Attack': {
        'danger_level': 'Medio',
        'explanation_it': "L'attaccante sta interagendo con il servizio FTP per accesso non autorizzato, brute force o trasferimento di file.",
        'advice': 'Disabilita accesso anonimo, preferisci SFTP o FTPS e limita gli IP autorizzati.',
    },
    'Web Crawl / Recon': {
        'danger_level': 'Basso',
        'explanation_it': "L'evento sembra attivita di ricognizione: scansione di path, banner o componenti vulnerabili in preparazione a un attacco successivo.",
        'advice': 'Riduci i banner informativi, monitora user agent sospetti e valuta rate limiting sulle route pubbliche.',
    },
    'Port Scan': {
        'danger_level': 'Basso',
        'explanation_it': 'L origine remota sta enumerando porte o servizi aperti per capire quali superfici di attacco sono disponibili.',
        'advice': 'Chiudi porte inutilizzate, segmenta la rete e usa firewall con logging per correlare le scansioni.',
    },
    'Unknown': {
        'danger_level': 'Basso',
        'explanation_it': "L'evento e reale ma non corrisponde ancora a una firma nota. Va conservato per analisi successive.",
        'advice': "Raccogli il payload, migliora le regole di classificazione e verifica se l'IP ricorre in altri tentativi.",
    },
}


def explain_attack(attack_type: str) -> Dict[str, str]:
    return EXPLAINERS.get(attack_type, EXPLAINERS['Unknown']).copy()
