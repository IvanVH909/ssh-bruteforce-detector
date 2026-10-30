#!/usr/bin/env python3
"""
ssh-bruteforce-detector
-----------------------
Analiza un log de OpenSSH (auth.log / secure / syslog) y detecta:

  * IPs que hacen fuerza bruta (muchos 'Failed password')
  * Tipo de ataque: adivinar la contraseña de un usuario vs. probar muchos usuarios
  * IPs que consiguieron entrar DESPUES de fallar muchas veces (posible compromiso)

Solo usa la libreria estandar de Python (sin dependencias).

Uso:
    python detector.py data/OpenSSH_2k.log
    python detector.py /var/log/auth.log --threshold 5 --output informe.md --json salida.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# 1. Expresiones regulares
# --------------------------------------------------------------------------- #
# Cabecera syslog:  "Dec 10 06:55:46 LabSZ sshd[24200]: <mensaje>"
SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*)$"
)

# "Failed password for [invalid user] <usuario> from <IP> port <n> ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>.+?) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

# "Accepted password|publickey for <usuario> from <IP> port <n> ssh2"
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\w[\w-]*) for (?P<user>.+?) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)

# syslog comprime lineas iguales: "message repeated 5 times: [ <linea original> ]"
REPEATED_RE = re.compile(r"message repeated (?P<n>\d+) times: \[\s*(?P<inner>.*?)\s*\]")


# --------------------------------------------------------------------------- #
# 2. Modelo de datos
# --------------------------------------------------------------------------- #
@dataclass
class IPStats:
    ip: str
    failures: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    users: Counter = field(default_factory=Counter)
    invalid_user_attempts: int = 0
    successes: list[tuple[datetime, str, str]] = field(default_factory=list)  # (ts, user, metodo)
    fail_times: list[datetime] = field(default_factory=list, repr=False)  # instante de cada fallo

    def register_failure(self, ts: datetime, user: str, invalid: bool, times: int = 1) -> None:
        self.failures += times
        self.users[user] += times
        if invalid:
            self.invalid_user_attempts += times
        self.fail_times.extend([ts] * times)
        self._touch(ts)

    def register_success(self, ts: datetime, user: str, method: str) -> None:
        self.successes.append((ts, user, method))
        self._touch(ts)

    def _touch(self, ts: datetime) -> None:
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

    # ---- Propiedades derivadas -------------------------------------------- #
    @property
    def duration_min(self) -> float:
        if not (self.first_seen and self.last_seen):
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds() / 60

    @property
    def rate_per_min(self) -> float:
        # Si todo ocurre en el mismo segundo, evitamos dividir por 0
        return self.failures / max(self.duration_min, 1.0)

    @property
    def attack_type(self) -> str:
        """Clasificacion sencilla segun a cuantos usuarios distintos ataca."""
        distinct = len(self.users)
        if distinct == 1:
            return "Adivinar contraseña de 1 usuario"
        if distinct >= 5:
            return "Diccionario de usuarios (spraying)"
        return "Pocos usuarios"

    def compromised(self, threshold: int) -> list[tuple[datetime, str, str]]:
        """Exitos que ocurren despues de >= threshold fallos previos desde la misma IP."""
        suspicious = []
        for ts, user, method in self.successes:
            prior_failures = self.failures_before(ts)
            if prior_failures >= threshold:
                suspicious.append((ts, user, method))
        return suspicious

    def failures_before(self, ts: datetime) -> int:
        """Cuantos fallos hubo desde esta IP hasta el instante ts."""
        return sum(1 for t in self.fail_times if t <= ts)


# --------------------------------------------------------------------------- #
# 3. Parseo
# --------------------------------------------------------------------------- #
def parse_timestamp(raw: str, year: int) -> datetime:
    """El syslog clasico NO incluye año, asi que hay que indicarlo."""
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")


def analyze(lines, year: int) -> tuple[dict[str, IPStats], dict]:
    """Recorre las lineas y devuelve estadisticas por IP + metricas globales."""
    stats: dict[str, IPStats] = {}
    meta = {"lines": 0, "sshd_lines": 0, "failed_events": 0, "accepted_events": 0}

    def get(ip: str) -> IPStats:
        if ip not in stats:
            stats[ip] = IPStats(ip=ip)
        return stats[ip]

    for raw_line in lines:
        meta["lines"] += 1
        m = SYSLOG_RE.match(raw_line.strip())
        if not m:
            continue
        meta["sshd_lines"] += 1
        ts = parse_timestamp(m["ts"], year)
        msg = m["msg"]

        # ¿Es una linea comprimida "message repeated N times: [...]"?
        times = 1
        rep = REPEATED_RE.search(msg)
        if rep:
            times = int(rep["n"])
            msg = rep["inner"]

        failed = FAILED_RE.search(msg)
        if failed:
            s = get(failed["ip"])
            s.register_failure(ts, failed["user"].strip(), bool(failed["invalid"]), times)
            meta["failed_events"] += times
            continue

        accepted = ACCEPTED_RE.search(msg)
        if accepted:
            get(accepted["ip"]).register_success(ts, accepted["user"], accepted["method"])
            meta["accepted_events"] += 1

    return stats, meta


# --------------------------------------------------------------------------- #
# 4. Informe
# --------------------------------------------------------------------------- #
def build_report(stats: dict[str, IPStats], meta: dict, threshold: int, source: str) -> str:
    attackers = sorted(
        (s for s in stats.values() if s.failures >= threshold),
        key=lambda s: s.failures,
        reverse=True,
    )
    compromised = [(s, s.compromised(threshold)) for s in stats.values() if s.compromised(threshold)]
    all_users = Counter()
    for s in stats.values():
        all_users.update(s.users)

    fmt = lambda d: d.strftime("%d-%b %H:%M:%S") if d else "-"
    out: list[str] = []
    out.append("# Informe de fuerza bruta SSH\n")
    out.append(f"- **Fichero analizado:** `{source}`")
    out.append(f"- **Lineas leidas:** {meta['lines']} (sshd: {meta['sshd_lines']})")
    out.append(f"- **Intentos fallidos:** {meta['failed_events']}")
    out.append(f"- **Accesos correctos:** {meta['accepted_events']}")
    out.append(f"- **IPs distintas:** {len(stats)}")
    out.append(f"- **IPs sospechosas (>= {threshold} fallos):** {len(attackers)}\n")

    out.append("## Posibles accesos conseguidos tras fuerza bruta\n")
    if compromised:
        out.append("> ⚠️ Una IP que falla muchas veces y luego entra es el caso mas grave: "
                   "hay que revisar la cuenta y la sesion.\n")
        out.append("| IP | Usuario | Metodo | Momento | Fallos previos |")
        out.append("|---|---|---|---|---|")
        for s, hits in compromised:
            for ts, user, method in hits:
                out.append(f"| `{s.ip}` | {user} | {method} | {fmt(ts)} | {s.failures_before(ts)} |")
    else:
        out.append("No se ha detectado ningun acceso correcto precedido de fuerza bruta.")
    out.append("")

    out.append("## IPs atacantes\n")
    out.append("| # | IP | Fallos | Usuarios distintos | Primer intento | Ultimo intento | Intentos/min | Tipo |")
    out.append("|---|---|---|---|---|---|---|---|")
    for i, s in enumerate(attackers, 1):
        out.append(
            f"| {i} | `{s.ip}` | {s.failures} | {len(s.users)} | {fmt(s.first_seen)} | "
            f"{fmt(s.last_seen)} | {s.rate_per_min:.1f} | {s.attack_type} |"
        )
    out.append("")

    out.append("## Usuarios mas atacados\n")
    out.append("| Usuario | Intentos |")
    out.append("|---|---|")
    for user, n in all_users.most_common(10):
        out.append(f"| `{user}` | {n} |")
    out.append("")

    out.append("## Recomendaciones\n")
    out.append("- Bloquear las IPs atacantes (firewall / `fail2ban`).")
    out.append("- Deshabilitar login de `root` por SSH (`PermitRootLogin no`) y usar claves en vez de contraseñas.")
    out.append("- Revisar las cuentas que aparecen en la tabla de accesos conseguidos (cambio de contraseña, "
               "auditoria de comandos ejecutados).")
    return "\n".join(out) + "\n"


def to_json(stats: dict[str, IPStats], threshold: int) -> dict:
    return {
        ip: {
            "failures": s.failures,
            "distinct_users": len(s.users),
            "first_seen": s.first_seen.isoformat() if s.first_seen else None,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            "attack_type": s.attack_type,
            "compromised": [
                {"ts": ts.isoformat(), "user": u, "method": m} for ts, u, m in s.compromised(threshold)
            ],
        }
        for ip, s in sorted(stats.items(), key=lambda kv: kv[1].failures, reverse=True)
        if s.failures >= threshold
    }


# --------------------------------------------------------------------------- #
# 5. CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Detecta fuerza bruta SSH en logs de OpenSSH.")
    ap.add_argument("logfile", type=Path, help="Ruta al auth.log / secure / syslog")
    ap.add_argument("--threshold", type=int, default=10, help="Fallos minimos para marcar una IP (def. 10)")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="Año del log (el syslog clasico no lo incluye)")
    ap.add_argument("--output", type=Path, default=Path("informe.md"), help="Informe Markdown de salida")
    ap.add_argument("--json", type=Path, help="Guardar tambien resultados en JSON")
    args = ap.parse_args(argv)

    if not args.logfile.exists():
        print(f"Error: no existe {args.logfile}", file=sys.stderr)
        return 1

    with args.logfile.open(encoding="utf-8", errors="replace") as fh:
        stats, meta = analyze(fh, args.year)

    report = build_report(stats, meta, args.threshold, args.logfile.name)
    args.output.write_text(report, encoding="utf-8")
    if args.json:
        args.json.write_text(json.dumps(to_json(stats, args.threshold), indent=2, ensure_ascii=False))

    print(f"OK -> {args.output}  ({meta['failed_events']} fallos, {len(stats)} IPs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
