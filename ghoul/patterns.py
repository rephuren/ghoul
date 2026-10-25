"""Распознавание реверс-шеллов и приёмов повышения привилегий (в духе GTFOBins)
в командах, которые бот вводит в поддельную оболочку. Только разбор текста:
ничего не исполняется и ни к чему не подключается."""
import re

HOST = r"([A-Za-z0-9.\-]+)"

REVSHELL = [
    ("bash /dev/tcp", re.compile(r"/dev/(?:tcp|udp)/" + HOST + r"/(\d{1,5})")),
    ("netcat -e/-c", re.compile(
        r"\b(?:nc|ncat|netcat)\b[^;|&]*?\s-\w*[ec]\b[^;|&]*?\s" + HOST + r"\s+(\d{2,5})\b")),
    ("netcat + mkfifo", re.compile(
        r"mkfifo\s+\S+[^;]*?\b(?:nc|ncat|netcat)\b\s+" + HOST + r"\s+(\d{2,5})")),
    ("socat", re.compile(r"\bsocat\b.*?(?:TCP4?|OPENSSL):" + HOST + r":(\d{2,5})", re.I)),
    ("python socket", re.compile(
        r"(?=.*\bsocket\b).*?\.connect\(\(\s*['\"]" + HOST + r"['\"]\s*,\s*(\d{2,5})\s*\)\)")),
    ("php fsockopen", re.compile(r"fsockopen\(\s*['\"]" + HOST + r"['\"]\s*,\s*(\d{2,5})")),
    ("powershell tcpclient", re.compile(
        r"TCPClient\(\s*['\"]" + HOST + r"['\"]\s*,\s*(\d{2,5})", re.I)),
]

PRIVESC = [
    ("sudo -l", re.compile(r"\bsudo\s+-l\b")),
    ("поиск suid", re.compile(r"\bfind\b[^;|&]*?-perm\s+(?:-?4000|-u=s|/4000)")),
    ("find -exec shell", re.compile(r"\bfind\b[^;|&]*?-exec\s+\S*(?:sh|bash)\b")),
    ("capabilities", re.compile(r"\bgetcap\s+-r\b")),
    ("bash -p", re.compile(r"\bbash\s+-p\b")),
    ("vim/less shell escape", re.compile(r"\b(?:vim?|less|more)\b[^;|&]*?(?:-c\s+['\"]?:?!|!\s*/bin/(?:ba)?sh)")),
    ("awk/python system()", re.compile(r"(?:awk|python3?|perl)\b[^;|&]*?(?:system\(|os\.system|pty\.spawn|setuid\(0\))")),
    ("linpeas/linenum", re.compile(r"\b(?:linpeas|linenum|les)\.sh\b", re.I)),
    ("чтение sudoers", re.compile(r"/etc/sudoers")),
]


def detect(line):
    """Вернуть список событий (kind, data) для строки команды."""
    events = []
    for name, rx in REVSHELL:
        m = rx.search(line)
        if m:
            events.append(("revshell", {"technique": name, "target": f"{m.group(1)}:{m.group(2)}"}))
            break
    for name, rx in PRIVESC:
        if rx.search(line):
            events.append(("privesc", {"technique": name}))
    return events
