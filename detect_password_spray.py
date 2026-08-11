"""
detect_password_spray.py

Replica localmente, en Python, la misma logica que la query KQL
(queries/detect_failed_logins.kql.txt) usada en Microsoft Sentinel
para detectar password spraying en Active Directory.

Por que existe este script:
Este proyecto es un laboratorio de aprendizaje. La query KQL esta
pensada para correr contra la tabla SecurityEvent de un Log Analytics
Workspace real. Para validar la logica de deteccion sin depender de
una infraestructura cloud completa (DCE/DCR/App Registration), este
script aplica la misma logica sobre el dataset JSON local.

Uso:
    python detect_password_spray.py ad_security_events.json
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Mismos umbrales que la query KQL:
# | where DistinctUsers >= 5 and FailedAttempts >= 10
MIN_DISTINCT_USERS = 5
MIN_FAILED_ATTEMPTS = 10
WINDOW_MINUTES = 10  # equivalente a bin(TimeGenerated, 10m)


def parse_time(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def bin_time(ts: datetime, window_minutes: int) -> datetime:
    """Redondea el timestamp hacia abajo al bloque de N minutos,
    equivalente a bin(TimeGenerated, Nm) en KQL."""
    discard = timedelta(
        minutes=ts.minute % window_minutes,
        seconds=ts.second,
        microseconds=ts.microsecond,
    )
    return ts - discard


def load_events(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_password_spray(events: list[dict]) -> list[dict]:
    # 1. where EventID == 4625
    failed_logins = [e for e in events if e.get("EventID") == 4625]

    # 2. summarize ... by IpAddress, bin(TimeGenerated, 10m)
    groups = defaultdict(lambda: {"attempts": 0, "users": set()})
    for e in failed_logins:
        ts = parse_time(e["TimeGenerated"])
        window = bin_time(ts, WINDOW_MINUTES)
        key = (e["IpAddress"], window)
        groups[key]["attempts"] += 1
        groups[key]["users"].add(e["TargetUserName"])

    # 3. where DistinctUsers >= 5 and FailedAttempts >= 10
    results = []
    for (ip, window), data in groups.items():
        distinct_users = len(data["users"])
        failed_attempts = data["attempts"]
        if distinct_users >= MIN_DISTINCT_USERS and failed_attempts >= MIN_FAILED_ATTEMPTS:
            results.append({
                "TimeGenerated": window.isoformat(),
                "IpAddress": ip,
                "FailedAttempts": failed_attempts,
                "DistinctUsers": distinct_users,
                "TargetedAccounts": sorted(data["users"]),
            })

    # 4. order by FailedAttempts desc
    results.sort(key=lambda r: r["FailedAttempts"], reverse=True)
    return results


def print_results(results: list[dict]) -> None:
    if not results:
        print("No se detectaron patrones de password spray con los umbrales actuales.")
        print(f"(Umbral: >= {MIN_DISTINCT_USERS} usuarios distintos y >= {MIN_FAILED_ATTEMPTS} intentos fallidos en ventanas de {WINDOW_MINUTES} min)")
        return

    print(f"{len(results)} alerta(s) de password spray detectada(s):\n")
    for r in results:
        print(f"  IP origen:        {r['IpAddress']}")
        print(f"  Ventana:          {r['TimeGenerated']}")
        print(f"  Intentos fallidos:{r['FailedAttempts']}")
        print(f"  Usuarios distintos:{r['DistinctUsers']}")
        print(f"  Cuentas targeteadas: {', '.join(r['TargetedAccounts'])}")
        print("-" * 50)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python detect_password_spray.py <archivo.json>")
        sys.exit(1)

    events = load_events(sys.argv[1])
    results = detect_password_spray(events)
    print_results(results)
