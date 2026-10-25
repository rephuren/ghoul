import argparse
import asyncio
import sys

from . import dashboard, demo, report, server
from .store import Store


def main():
    parser = argparse.ArgumentParser(prog="ghoul", description="SSH honeypot с поддельной оболочкой")
    sub = parser.add_subparsers(dest="mode", required=True)

    run = sub.add_parser("run", help="запустить приманку")
    run.add_argument("--host", default="127.0.0.1", help="адрес (по умолчанию только localhost)")
    run.add_argument("--port", type=int, default=2222)
    run.add_argument("--db", default="data/ghoul.db")
    run.add_argument("--key", default="data/host_key")
    run.add_argument("--hostname", default="srv04")
    run.add_argument("--accept-after", type=int, default=2, help="сколько паролей отклонить перед входом")

    rep = sub.add_parser("report", help="отчёт по собранным данным")
    rep.add_argument("--db", default="data/ghoul.db")
    rep.add_argument("--no-color", action="store_true")

    dash = sub.add_parser("dashboard", help="локальный веб-дашборд")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8080)
    dash.add_argument("--db", default="data/ghoul.db")

    seed = sub.add_parser("seed-demo", help="заполнить базу синтетическими данными для демо")
    seed.add_argument("--db", default="data/demo.db")

    args = parser.parse_args()
    if args.mode == "dashboard":
        dashboard.serve(args.host, args.port, args.db)
        return
    if args.mode == "seed-demo":
        demo.seed(args.db)
        print(f"демо-данные записаны в {args.db}")
        return
    if args.mode == "report":
        store = Store(args.db)
        sys.stdout.write(report.build(store, color=not args.no_color and sys.stdout.isatty()))
        return

    async def serve():
        srv, store = await server.start(args.host, args.port, args.db, args.key, args.hostname, args.accept_after)
        print(f"ghoul слушает {args.host}:{args.port}, база {args.db}")
        try:
            await srv.wait_closed()
        finally:
            store.close()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


main()
