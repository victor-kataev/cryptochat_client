import argparse
import asyncio

from dotenv import load_dotenv
load_dotenv()

from client.auth import command_start


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure chat in CLI")

    subparsers = parser.add_subparsers(dest="command")

    start_parser = subparsers.add_parser("start", help="Start chat")
    start_parser.set_defaults(handler=command_start)

    subparsers.add_parser("clean/logout", help="Removes the credential folder from the current machine")

    args = parser.parse_args()

    if hasattr(args, 'handler'):
        asyncio.run(args.handler(args))
    else:
        asyncio.run(command_start())
