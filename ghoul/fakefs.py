"""Поддельная файловая система в памяти. Реальный диск не затрагивается."""
import posixpath

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "sshd:x:106:65534::/run/sshd:/usr/sbin/nologin\n"
    "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
)

SHADOW_DENIED = "cat: /etc/shadow: Permission denied\n"


def default_tree(hostname):
    return {
        "bin": {},
        "etc": {
            "passwd": PASSWD,
            "hostname": hostname + "\n",
            "issue": "Debian GNU/Linux 12 \\n \\l\n",
            "os-release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\n',
            "shadow": None,
        },
        "home": {"admin": {".bash_history": ""}},
        "root": {".bashrc": "# ~/.bashrc\n", ".ssh": {}},
        "tmp": {},
        "var": {"log": {"auth.log": "", "syslog": ""}, "www": {}},
        "usr": {"bin": {}},
        "proc": {
            "cpuinfo": "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n",
            "version": "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org)\n",
        },
    }


class FakeFS:
    def __init__(self, hostname="srv04"):
        self.root = default_tree(hostname)
        self.cwd = "/root"

    def resolve(self, path):
        if not path:
            return self.cwd
        if path.startswith("~"):
            path = "/root" + path[1:]
        if not path.startswith("/"):
            path = posixpath.join(self.cwd, path)
        return posixpath.normpath(path)

    def _walk(self, abspath):
        node = self.root
        for part in [p for p in abspath.split("/") if p]:
            if not isinstance(node, dict) or part not in node:
                return KeyError
            node = node[part]
        return node

    def exists(self, path):
        return self._walk(self.resolve(path)) is not KeyError

    def is_dir(self, path):
        return isinstance(self._walk(self.resolve(path)), dict)

    def read(self, path):
        """Вернуть текст файла или None/KeyError-маркер. None = нет прав."""
        return self._walk(self.resolve(path))

    def listdir(self, path):
        node = self._walk(self.resolve(path))
        return sorted(node) if isinstance(node, dict) else None

    def write(self, path, content, append=False):
        abspath = self.resolve(path)
        parent_path, name = posixpath.split(abspath)
        parent = self._walk(parent_path)
        if not isinstance(parent, dict):
            return False
        if append and isinstance(parent.get(name), str):
            parent[name] += content
        else:
            parent[name] = content
        return True

    def mkdir(self, path):
        abspath = self.resolve(path)
        parent_path, name = posixpath.split(abspath)
        parent = self._walk(parent_path)
        if not isinstance(parent, dict) or name in parent:
            return False
        parent[name] = {}
        return True

    def remove(self, path):
        abspath = self.resolve(path)
        parent_path, name = posixpath.split(abspath)
        parent = self._walk(parent_path)
        if isinstance(parent, dict) and name in parent:
            del parent[name]
            return True
        return False

    def chdir(self, path):
        abspath = self.resolve(path)
        if isinstance(self._walk(abspath), dict):
            self.cwd = abspath
            return True
        return False
