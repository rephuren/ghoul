"""Текстовый отчёт по собранным данным."""
from collections import Counter

DIM = "\033[2m"
RED = "\033[38;2;179;0;15m"
RESET = "\033[0m"


def _section(title, rows, limit=10):
    lines = [f"\n{RED}▓ {title}{RESET}"]
    if not rows:
        lines.append(f"  {DIM}пусто{RESET}")
    for value, count in rows[:limit]:
        lines.append(f"  {count:>5}  {value}")
    return lines


def build(store, color=True):
    db = store.db
    total = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    authed = db.execute("SELECT COUNT(*) FROM sessions WHERE authed = 1").fetchone()[0]
    ips = db.execute("SELECT COUNT(DISTINCT src_ip) FROM sessions").fetchone()[0]

    creds = Counter(
        f"{d['username']}:{d['password']}" for _, _, d in store.events("auth")
    )
    users = Counter(d["username"] for _, _, d in store.events("auth"))
    cmds = Counter(d["cmd"] for _, _, d in store.events("command"))
    urls = Counter(d["url"] for _, _, d in store.events("url"))
    top_ips = db.execute(
        "SELECT src_ip, COUNT(*) c FROM sessions GROUP BY src_ip ORDER BY c DESC LIMIT 10"
    ).fetchall()
    clients = Counter(
        row["client_version"] for row in db.execute("SELECT client_version FROM sessions") if row["client_version"]
    )

    lines = [
        f"{RED}░▒▓█ ghoul — отчёт █▓▒░{RESET}",
        f"  сессий: {total}   с входом: {authed}   уникальных IP: {ips}",
    ]
    lines += _section("логин:пароль", creds.most_common())
    lines += _section("логины", users.most_common())
    lines += _section("IP-адреса", [(r["src_ip"], r["c"]) for r in top_ips])
    lines += _section("команды", cmds.most_common())
    lines += _section("URL из команд (IOC)", urls.most_common())
    lines += _section("SSH-клиенты", clients.most_common())
    text = "\n".join(lines) + "\n"
    if not color:
        for code in (DIM, RED, RESET):
            text = text.replace(code, "")
    return text
