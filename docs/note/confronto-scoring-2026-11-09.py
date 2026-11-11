"""Confronto del 09/11/2026: scoring del codice di allora (A) contro Architettura §5 (B).

Script autonomo, non importa il backend: la formula A non esiste più nel codice dal passo 4.
Uso: python confronto-scoring-2026-11-09.py
Gli scenari sono inventati; CVSS ed EPSS sono valori di prova, non dati reali.
"""

# --- A: formula del codice prima del 09/11/2026 ---------------------------------------------
A_W = {"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10}


def a_level(v):
    return "critical" if v >= 0.9 else "high" if v >= 0.7 else "medium" if v >= 0.4 else "low"


def a_score(events):
    total = 0.0
    for cvss, kev, epss, conf, age in events:
        sev = 1.0 if kev else cvss / 10
        rec = min(1.0, max(0.0, 1 - age / 90))
        boost = min(epss * 2, 0.3)
        total += sev * A_W["severity"] + conf * A_W["confidence"] + rec * A_W["recency"] + boost * A_W["epss"]
    return total  # nessun tetto


# --- B: Architettura §5 (quella adottata) ------------------------------------------------------
def b_level(v):
    return "critical" if v >= 0.7 else "high" if v >= 0.4 else "medium" if v >= 0.2 else "low"


def b_recency(age):
    return 1.0 if age < 7 else 0.5 if age < 30 else 0.2


def b_score(events, exposure, impact):
    total = 0.0
    for cvss, kev, _epss, conf, age in events:
        s_base = cvss / 10 * 0.5 + (1.0 if kev else conf) * 0.3 + b_recency(age) * 0.2
        total += s_base * exposure * impact * 1.0  # alpha vulnerabilità = 1.0
    return min(1.0, total)


KEV = (9.8, True, 0.9, 0.9, 0)  # (cvss, in_kev, epss, confidenza match, giorni)
SCENARI = [
    ("1", "Web esposto, dati sensibili: CVE critica in KEV, oggi", [KEV], 1.0, 1.0),
    ("2", "Stesso asset e CVE, 60 giorni fa", [(9.8, True, 0.9, 0.9, 60)], 1.0, 1.0),
    ("3", "Web esposto: CVE media (CVSS 5.3, EPSS 0.02), oggi", [(5.3, False, 0.02, 0.9, 0)], 1.0, 1.0),
    ("4", "Web esposto: CVE alta (CVSS 7.5), versione non nota", [(7.5, False, 0.4, 0.7, 0)], 1.0, 1.0),
    ("5", "Web esposto: 5 CVE medie, 10 giorni fa", [(5.0, False, 0.01, 0.9, 10)] * 5, 1.0, 1.0),
    ("6", "Server interno non critico: CVE in KEV", [KEV], 0.2, 0.3),
    ("7", "DMZ, business critical: CVE in KEV", [KEV], 0.5, 0.6),
]

if __name__ == "__main__":
    print("| # | Scenario | A | livello A | B | livello B |")
    for n, desc, events, e, i in SCENARI:
        a, b = a_score(events), b_score(events, e, i)
        print(f"| {n} | {desc} | {a:.2f} | {a_level(a)} | {b:.2f} | {b_level(b)} |")
