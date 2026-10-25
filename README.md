# ghoul

SSH-приманка с поддельной оболочкой. Принимает пароль после нескольких попыток, отдаёт правдоподобный Debian-шелл, пишет логины, пароли, команды и URL из них в SQLite. Ничего не исполняет и никуда не ходит в сеть: `wget`/`curl` только имитируются и фиксируются как IOC.

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m ghoul run --port 2222     # по умолчанию слушает только 127.0.0.1
.venv/bin/python -m ghoul report              # сводка: пароли, IP, команды, URL
.venv/bin/python -m ghoul dashboard           # веб-дашборд на http://127.0.0.1:8080
.venv/bin/python -m ghoul seed-demo           # синтетические данные в data/demo.db
.venv/bin/python -m ghoul dashboard --db data/demo.db
.venv/bin/python -m pytest
```

Дашборд слушает только localhost и ничего не рендерит через `innerHTML`: все строки приходят от атакующих.

## Дальше
- кластеризация сессий по поведению и отпечатку клиента
- запись tty-сессий и реплей
