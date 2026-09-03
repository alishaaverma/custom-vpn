from __future__ import annotations

import argparse
import json
import secrets

from client.client import VPNClient
from config.settings import load_client_settings, load_server_settings
from helpers.logger import setup_logging
from helpers.platform_info import require_supported_runtime, runtime_summary
from server.server import VPNServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="custom-python-vpn",
        description="Terminal-only Python overlay tunnel for project access (Windows + Ubuntu).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="Run the central overlay server")
    p_server.add_argument("--config", required=True)

    p_client = sub.add_parser("client", help="Run a client agent and configured local forwards")
    p_client.add_argument("--config", required=True)

    sub.add_parser("gen-psk", help="Generate a 256-bit PSK as hex")
    sub.add_parser("check", help="Check Python/OpenSSL runtime support")
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "gen-psk":
        print(secrets.token_hex(32))
        return

    if args.command == "check":
        print(json.dumps(runtime_summary(), indent=2))
        require_supported_runtime()
        print("Runtime OK")
        return

    require_supported_runtime()

    if args.command == "server":
        settings = load_server_settings(args.config)
        setup_logging(settings.log_level, settings.log_file)
        VPNServer(settings).serve_forever()
        return

    if args.command == "client":
        settings = load_client_settings(args.config)
        setup_logging(settings.log_level, settings.log_file)
        VPNClient(settings).run_forever()
        return


if __name__ == "__main__":
    main()
