import argparse
import json

from pipeline.orchestrator import Orchestrator


def _print(obj):
    print(json.dumps(obj, indent=2, default=str))


def cmd_discover(args):
    orch = Orchestrator()
    res = orch.discover(args.target)
    _print(res)


def cmd_scan(args):
    orch = Orchestrator()
    res = orch.scan(args.target)
    _print(res)


def cmd_report(args):
    orch = Orchestrator()
    findings = orch.report(args.asset)
    _print(findings)


def cmd_verify(args):
    orch = Orchestrator()
    res = orch.verify(write_test_doc=args.write_test_doc)
    _print(res)


def main():
    parser = argparse.ArgumentParser(description="Surface + OWASP signal scanner (single node)")
    sub = parser.add_subparsers()

    p_disc = sub.add_parser("discover", help="Pass-0 discovery (DNS/TLS/HEAD)")
    p_disc.add_argument("target")
    p_disc.set_defaults(func=cmd_discover)

    p_scan = sub.add_parser("scan", help="Pass-1 + Pass-2 scan")
    p_scan.add_argument("target")
    p_scan.set_defaults(func=cmd_scan)

    p_report = sub.add_parser("report", help="List findings for asset")
    p_report.add_argument("asset")
    p_report.set_defaults(func=cmd_report)

    p_verify = sub.add_parser("verify", help="Config + ES connectivity check")
    p_verify.add_argument("--write-test-doc", action="store_true", default=False, help="write test doc to ES")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
