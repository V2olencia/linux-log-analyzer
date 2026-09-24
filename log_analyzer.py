#!/usr/bin/env python3
"""Analyze a small, documented subset of Linux authentication logs."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SSH_FAILED = re.compile(
    r"sshd\[\d+\]: Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+)"
)
SSH_ACCEPTED = re.compile(
    r"sshd\[\d+\]: Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)"
)
SUDO_FAILED = re.compile(
    r"sudo: pam_unix\(sudo:auth\): authentication failure;.*\buser=(?P<user>\S+)"
)


@dataclass(frozen=True)
class AuthEvent:
    event_type: str
    user: str | None = None
    source_ip: str | None = None


def valid_ip(value: str) -> str | None:
    """Return a normalized IP address or None when the value is invalid."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def parse_line(line: str) -> AuthEvent | None:
    """Parse one supported auth.log line."""
    if match := SSH_FAILED.search(line):
        return AuthEvent(
            event_type="ssh_failed",
            user=match.group("user"),
            source_ip=valid_ip(match.group("ip")),
        )

    if match := SSH_ACCEPTED.search(line):
        return AuthEvent(
            event_type="ssh_accepted",
            user=match.group("user"),
            source_ip=valid_ip(match.group("ip")),
        )

    if match := SUDO_FAILED.search(line):
        return AuthEvent(event_type="sudo_failed", user=match.group("user"))

    return None


def analyze(lines: Iterable[str], threshold: int = 5) -> dict[str, object]:
    """Aggregate authentication events and flag repeated SSH failures."""
    if threshold < 1:
        raise ValueError("threshold deve ser maior ou igual a 1")

    event_counts: Counter[str] = Counter()
    failed_by_ip: Counter[str] = Counter()
    targeted_users: Counter[str] = Counter()
    total_lines = 0
    recognized_lines = 0

    for line in lines:
        total_lines += 1
        event = parse_line(line)
        if event is None:
            continue

        recognized_lines += 1
        event_counts[event.event_type] += 1

        if event.event_type == "ssh_failed":
            if event.source_ip:
                failed_by_ip[event.source_ip] += 1
            if event.user:
                targeted_users[event.user] += 1

    alerts = [
        {"source_ip": source_ip, "failures": failures}
        for source_ip, failures in failed_by_ip.most_common()
        if failures >= threshold
    ]

    return {
        "total_lines": total_lines,
        "recognized_lines": recognized_lines,
        "event_counts": dict(event_counts),
        "failed_by_ip": dict(failed_by_ip.most_common()),
        "targeted_users": dict(targeted_users.most_common()),
        "brute_force_alerts": alerts,
        "threshold": threshold,
    }


def render_text(summary: dict[str, object]) -> str:
    """Render a concise terminal report."""
    event_counts = summary["event_counts"]
    failed_by_ip = summary["failed_by_ip"]
    targeted_users = summary["targeted_users"]
    alerts = summary["brute_force_alerts"]

    lines = [
        "Resumo de autenticacao",
        "=" * 24,
        f"Linhas lidas: {summary['total_lines']}",
        f"Eventos reconhecidos: {summary['recognized_lines']}",
        f"Falhas SSH: {event_counts.get('ssh_failed', 0)}",
        f"Acessos SSH aceitos: {event_counts.get('ssh_accepted', 0)}",
        f"Falhas de sudo: {event_counts.get('sudo_failed', 0)}",
        "",
        "Falhas SSH por IP:",
    ]

    lines.extend(
        f"- {source_ip}: {count}"
        for source_ip, count in failed_by_ip.items()
    )
    if not failed_by_ip:
        lines.append("- nenhuma")

    lines.append("")
    lines.append("Usuarios mais visados:")
    lines.extend(f"- {user}: {count}" for user, count in targeted_users.items())
    if not targeted_users:
        lines.append("- nenhum")

    lines.append("")
    lines.append(f"Alertas (limiar: {summary['threshold']}):")
    lines.extend(
        f"- possivel forca bruta de {alert['source_ip']} "
        f"({alert['failures']} falhas)"
        for alert in alerts
    )
    if not alerts:
        lines.append("- nenhum")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resume eventos SSH e sudo em um arquivo auth.log."
    )
    parser.add_argument("log_file", type=Path, help="caminho do arquivo de log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="numero de falhas SSH por IP para gerar alerta (padrao: 5)",
    )
    parser.add_argument("--json", action="store_true", help="gera saida JSON")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.log_file.is_file():
        print(f"Erro: arquivo nao encontrado: {args.log_file}")
        return 2

    try:
        with args.log_file.open(encoding="utf-8", errors="replace") as log_file:
            summary = analyze(log_file, threshold=args.threshold)
    except (OSError, ValueError) as error:
        print(f"Erro: {error}")
        return 2

    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(render_text(summary))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
