"""Поддельная оболочка. Ничего не исполняет и никуда не ходит в сеть:
каждая команда только возвращает правдоподобный текст и пишет событие."""
import re
import shlex

from . import patterns
from .fakefs import FakeFS, SHADOW_DENIED

URL_RE = re.compile(r"(?:https?|ftp|tftp)://[^\s'\"<>|;&]+", re.I)
OPERATORS = {";", "&&", "||", "&", "|"}
MAX_DEPTH = 3

UNAME = "Linux {host} 6.1.0-18-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01) x86_64 GNU/Linux"
PS_OUT = (
    "  PID TTY          TIME CMD\n"
    "    1 ?        00:00:03 systemd\n"
    "  412 ?        00:00:00 sshd\n"
    "  733 pts/0    00:00:00 bash\n"
    "  761 pts/0    00:00:00 ps\n"
)
IFCONFIG = (
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
    "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
    "        ether 52:54:00:12:34:56  txqueuelen 1000  (Ethernet)\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\n"
)
FREE_OUT = (
    "               total        used        free      shared  buff/cache   available\n"
    "Mem:            1987         412         901           3         673        1415\n"
    "Swap:              0           0           0\n"
)
DF_OUT = (
    "Filesystem      Size  Used Avail Use% Mounted on\n"
    "/dev/vda1        25G  4.1G   20G  17% /\n"
    "tmpfs           994M     0  994M   0% /dev/shm\n"
)


class Shell:
    def __init__(self, hostname="srv04", on_event=None):
        self.hostname = hostname
        self.fs = FakeFS(hostname)
        self.on_event = on_event or (lambda kind, data: None)
        self.env = {"HOME": "/root", "USER": "root", "SHELL": "/bin/bash", "PATH": "/usr/bin:/bin"}
        self.exit_requested = False
        self.history = []

    @property
    def prompt(self):
        cwd = self.fs.cwd
        shown = "~" if cwd == "/root" else cwd
        if cwd.startswith("/root/"):
            shown = "~" + cwd[len("/root"):]
        return f"root@{self.hostname}:{shown}# "

    def run_line(self, line, _depth=0):
        """Выполнить строку, вернуть текст вывода."""
        line = line.strip()
        if not line:
            return ""
        if _depth == 0:
            self.history.append(line)
            self.on_event("command", {"cmd": line})
            for url in URL_RE.findall(line):
                self.on_event("url", {"url": url, "cmd": line})
            for kind, data in patterns.detect(line):
                self.on_event(kind, data)
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            return "bash: syntax error: unexpected end of file\n"

        out = []
        for segment in self._segments(tokens):
            out.append(self._run_pipeline(segment, _depth))
            if self.exit_requested:
                break
        return "".join(out)

    @staticmethod
    def _segments(tokens):
        seg = []
        for tok in tokens:
            if tok in (";", "&&", "||", "&"):
                if seg:
                    yield seg
                seg = []
            else:
                seg.append(tok)
        if seg:
            yield seg

    def _run_pipeline(self, tokens, depth):
        parts, cur = [], []
        for tok in tokens:
            if tok == "|":
                parts.append(cur)
                cur = []
            else:
                cur.append(tok)
        parts.append(cur)
        if len(parts) > 1:
            sink = parts[-1][0] if parts[-1] else ""
            if sink in ("sh", "bash", "zsh", "dash"):
                self.on_event("pipe_to_shell", {"source": " ".join(parts[0])})
        return self._run_simple(parts[0], depth)

    def _run_simple(self, tokens, depth):
        redirect, append = None, False
        args = []
        it = iter(tokens)
        for tok in it:
            if tok in (">", ">>"):
                redirect = next(it, None)
                append = tok == ">>"
            elif tok in ("<", "<<"):
                next(it, None)
            else:
                args.append(tok)
        while args and "=" in args[0] and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", args[0]):
            key, _, val = args.pop(0).partition("=")
            self.env[key] = val
        if not args:
            return ""
        if args[0] == "sudo" and len(args) > 1:
            if args[1] == "-l":
                return "User root may run the following commands on " + self.hostname + ":\n    (ALL : ALL) ALL\n"
            args = args[1:]
        name, rest = args[0], args[1:]
        handler = getattr(self, "cmd_" + re.sub(r"\W", "_", name.split("/")[-1]), None)
        if name.startswith("./") or (name.startswith("/") and self.fs.exists(name) and not self.fs.is_dir(name)):
            self.on_event("exec", {"path": self.fs.resolve(name), "args": rest})
            return ""
        if handler is None:
            output = f"bash: {name}: command not found\n"
        elif name in ("sh", "bash") and depth >= MAX_DEPTH:
            output = ""
        else:
            output = handler(rest, depth) or ""
        if redirect:
            self.fs.write(redirect, output, append=append)
            return ""
        return output

    # ---- команды ----

    def cmd_exit(self, args, depth):
        self.exit_requested = True

    cmd_logout = cmd_exit

    def cmd_pwd(self, args, depth):
        return self.fs.cwd + "\n"

    def cmd_cd(self, args, depth):
        target = args[0] if args else "~"
        if not self.fs.chdir(target):
            return f"bash: cd: {target}: No such file or directory\n"

    def cmd_ls(self, args, depth):
        flags = "".join(a.lstrip("-") for a in args if a.startswith("-"))
        paths = [a for a in args if not a.startswith("-")] or ["."]
        out = []
        for path in paths:
            names = self.fs.listdir(path)
            if names is None:
                if self.fs.exists(path):
                    out.append(path + "\n")
                else:
                    out.append(f"ls: cannot access '{path}': No such file or directory\n")
                continue
            if "a" not in flags:
                names = [n for n in names if not n.startswith(".")]
            if "l" in flags:
                for n in names:
                    full = self.fs.resolve(path) + "/" + n
                    kind = "d" if self.fs.is_dir(full) else "-"
                    out.append(f"{kind}rwxr-xr-x 2 root root 4096 Feb  1 03:12 {n}\n")
            elif names:
                out.append("  ".join(names) + "\n")
        return "".join(out)

    def cmd_cat(self, args, depth):
        out = []
        for path in args:
            if path.startswith("-"):
                continue
            if self.fs.resolve(path) == "/etc/shadow":
                out.append(SHADOW_DENIED)
                continue
            content = self.fs.read(path)
            if isinstance(content, str):
                out.append(content)
            elif isinstance(content, dict):
                out.append(f"cat: {path}: Is a directory\n")
            else:
                out.append(f"cat: {path}: No such file or directory\n")
        return "".join(out)

    def cmd_echo(self, args, depth):
        newline, interpret = True, False
        while args and args[0] in ("-n", "-e", "-ne", "-en"):
            flag = args.pop(0)
            newline = newline and "n" not in flag
            interpret = interpret or "e" in flag
        text = " ".join(self._expand(a) for a in args)
        if interpret:
            try:
                text = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
            except UnicodeDecodeError:
                pass
        return text + ("\n" if newline else "")

    def _expand(self, word):
        return re.sub(r"\$(\w+)", lambda m: self.env.get(m.group(1), ""), word)

    def cmd_whoami(self, args, depth):
        return "root\n"

    def cmd_id(self, args, depth):
        return "uid=0(root) gid=0(root) groups=0(root)\n"

    def cmd_hostname(self, args, depth):
        return self.hostname + "\n"

    def cmd_uname(self, args, depth):
        if not args:
            return "Linux\n"
        flags = "".join(a.lstrip("-") for a in args)
        if "a" in flags:
            return UNAME.format(host=self.hostname) + "\n"
        parts = []
        if "s" in flags:
            parts.append("Linux")
        if "n" in flags:
            parts.append(self.hostname)
        if "r" in flags:
            parts.append("6.1.0-18-amd64")
        if "m" in flags:
            parts.append("x86_64")
        return " ".join(parts) + "\n"

    def cmd_uptime(self, args, depth):
        return " 03:14:07 up 41 days,  2:19,  1 user,  load average: 0.00, 0.01, 0.00\n"

    def cmd_w(self, args, depth):
        return (
            " 03:14:07 up 41 days,  2:19,  1 user,  load average: 0.00, 0.01, 0.00\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "root     pts/0    10.0.2.2         03:13    0.00s  0.02s  0.00s w\n"
        )

    def cmd_ps(self, args, depth):
        return PS_OUT

    def cmd_free(self, args, depth):
        return FREE_OUT

    def cmd_df(self, args, depth):
        return DF_OUT

    def cmd_nproc(self, args, depth):
        return "2\n"

    def cmd_ifconfig(self, args, depth):
        return IFCONFIG

    def cmd_ip(self, args, depth):
        return IFCONFIG

    def cmd_history(self, args, depth):
        return "".join(f"{i:5d}  {h}\n" for i, h in enumerate(self.history, 1))

    def cmd_crontab(self, args, depth):
        return "no crontab for root\n"

    def cmd_mkdir(self, args, depth):
        out = []
        for path in [a for a in args if not a.startswith("-")]:
            if not self.fs.mkdir(path):
                out.append(f"mkdir: cannot create directory '{path}': File exists\n")
        return "".join(out)

    def cmd_touch(self, args, depth):
        for path in args:
            if not self.fs.exists(path):
                self.fs.write(path, "")

    def cmd_rm(self, args, depth):
        for path in [a for a in args if not a.startswith("-")]:
            self.fs.remove(path)

    def cmd_export(self, args, depth):
        for a in args:
            key, _, val = a.partition("=")
            self.env[key] = val

    def cmd_unset(self, args, depth):
        for a in args:
            self.env.pop(a, None)

    def cmd_chmod(self, args, depth):
        return ""

    cmd_chown = cmd_chmod
    cmd_clear = cmd_chmod
    cmd_sleep = cmd_chmod
    cmd_true = cmd_chmod
    cmd_nohup = cmd_chmod
    cmd_set = cmd_chmod
    cmd_kill = cmd_chmod
    cmd_pkill = cmd_chmod
    cmd_killall = cmd_chmod

    def cmd_false(self, args, depth):
        return ""

    def cmd_find(self, args, depth):
        if "-perm" in args:
            return "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/su\n/usr/bin/mount\n"
        return ""

    def cmd_getcap(self, args, depth):
        return ""

    def cmd_passwd(self, args, depth):
        return "passwd: password updated successfully\n"

    def cmd_sh(self, args, depth):
        if args and args[0] == "-c" and len(args) > 1:
            return self.run_line(args[1], _depth=depth + 1)
        return ""

    cmd_bash = cmd_sh
    cmd_dash = cmd_sh

    def cmd_wget(self, args, depth):
        urls = [a for a in args if URL_RE.match(a)]
        if not urls:
            return "wget: missing URL\n"
        url = urls[0]
        host = re.sub(r"^\w+://", "", url).split("/")[0]
        if "-O" in args and args.index("-O") + 1 < len(args):
            dest = args[args.index("-O") + 1]
        else:
            dest = url.rstrip("/").rsplit("/", 1)[-1] or "index.html"
        if dest != "-":
            self.fs.write(dest, "#!/bin/sh\n")
        self.on_event("download", {"url": url, "saved_as": dest})
        return (
            f"--03:14:09--  {url}\n"
            f"Resolving {host}... connected.\n"
            "HTTP request sent, awaiting response... 200 OK\n"
            f"Saving to: '{dest}'\n\n"
            f"'{dest}' saved [1337/1337]\n"
        )

    def cmd_curl(self, args, depth):
        urls = [a for a in args if URL_RE.match(a)]
        if not urls:
            return "curl: try 'curl --help' for more information\n"
        self.on_event("download", {"url": urls[0], "saved_as": None})
        for flag in ("-o", "-O"):
            if flag in args and flag == "-o" and args.index(flag) + 1 < len(args):
                self.fs.write(args[args.index(flag) + 1], "#!/bin/sh\n")
        return ""

    cmd_tftp = cmd_curl
    cmd_ftpget = cmd_curl
