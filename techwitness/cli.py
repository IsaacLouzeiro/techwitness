import argparse
import json
import os
import sys

from . import __version__, output
from .fetch import DEFAULT_PORTS, DEFAULT_UA, Client
from .scanner import Options, Scanner


def positive(text):
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return n


def header(text):
    name, sep, value = text.partition(":")
    if not sep or not name.strip() or "\r" in text or "\n" in text:
        raise argparse.ArgumentTypeError("use 'Name: value'")
    return name.strip(), value.strip()


def port_list(text):
    try:
        ports = tuple(dict.fromkeys(int(p) for p in text.split(",")))
    except ValueError:
        raise argparse.ArgumentTypeError("use numbers separated by commas") from None
    if not all(0 < p < 65536 for p in ports):
        raise argparse.ArgumentTypeError("ports go from 1 to 65535")
    return ports


def build_parser():
    p = argparse.ArgumentParser(
        prog="techwitness",
        description="Identifies the technologies behind a website: banners, HTML, scripts, links, cookies and TLS.",
        epilog="Only scan systems you own or are authorized to test.")
    p.add_argument("targets", nargs="*", metavar="TARGET", help="URL or host")
    p.add_argument("-f", "--file", help="file with one target per line (# starts a comment)")
    p.add_argument("-a", "--aggression", type=int, choices=(1, 2, 3), default=2,
                   help="1: first page only; 2: crawl, scripts, 404 page, robots.txt (default); "
                        "3: also known paths and source maps")
    p.add_argument("-b", "--banners", action="store_true",
                   help="also read the banner of TCP services (ports "
                        + ",".join(map(str, DEFAULT_PORTS)) + ")")
    p.add_argument("-p", "--ports", type=port_list, metavar="LIST", help="ports for the banners, e.g. 22,2222")
    p.add_argument("--max-pages", type=positive, default=10, help="pages to crawl (default: 10)")
    p.add_argument("--max-scripts", type=positive, default=30, help="JS files to download (default: 30)")
    p.add_argument("--threads", type=positive, default=8, help="parallel requests (default: 8)")
    p.add_argument("--timeout", type=positive, default=10, help="seconds per request (default: 10)")
    p.add_argument("--no-redirect", action="store_true", help="do not follow redirects of the target URL")
    p.add_argument("-H", "--header", type=header, action="append", default=[], metavar="'NAME: VALUE'",
                   help="extra header, only sent to the target host (can be repeated)")
    p.add_argument("-c", "--cookie", help="Cookie header, only sent to the target host")
    p.add_argument("-A", "--user-agent", default=DEFAULT_UA)
    p.add_argument("-x", "--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("-l", "--links", action="store_true",
                   help="list links, API endpoints, subdomains and third-party hosts")
    p.add_argument("-v", "--verbose", action="store_true", help="show all the evidence")
    p.add_argument("-q", "--quiet", action="store_true", help="no logo and no progress messages")
    p.add_argument("-j", "--json", action="store_true", help="print JSON instead of text")
    p.add_argument("-o", "--output", help="save to a file: .json, .csv or .txt")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"techwitness {__version__}")
    return p


def read_targets(args, parser):
    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8-sig") as fh:
                targets += [line.strip() for line in fh if not line.lstrip().startswith("#")]
        except (OSError, UnicodeError) as exc:
            parser.error(f"cannot read {args.file}: {exc}")
    targets = list(dict.fromkeys(t for t in targets if t))
    if not targets:
        parser.error("no target given")
    return targets


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    targets = read_targets(args, parser)
    ext = os.path.splitext(args.output)[1].lower() if args.output else ""
    if args.output and ext not in (".json", ".csv", ".txt"):
        parser.error("--output must end in .json, .csv or .txt")
    headers = args.header + ([("Cookie", args.cookie)] if args.cookie else [])
    ports = args.ports or (DEFAULT_PORTS if args.banners else ())
    if ports and args.proxy:
        parser.error("TCP banners cannot go through the proxy; use one or the other")

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    st = output.Style(sys.stdout.isatty() and not args.no_color and not os.environ.get("NO_COLOR")
                      and os.environ.get("TERM") != "dumb")
    show_progress = not args.quiet and sys.stderr.isatty()

    def log(msg):
        if show_progress:
            print(f"[~] {output.safe(msg)}", file=sys.stderr)

    if not args.json and not args.quiet:
        output.print_logo(st, sys.stdout)
    opts = Options(args.aggression, args.max_pages, args.max_scripts, args.threads, ports, not args.no_redirect)
    results, interrupted = [], False
    for target in targets:
        try:
            # one client per target: custom headers stay with the host they were allowed for
            client = Client(args.timeout, args.user_agent, headers, args.proxy)
        except ValueError as exc:
            parser.error(str(exc))
        log(f"scanning {target}")
        try:
            res = Scanner(client, opts, log).scan(target)
        except KeyboardInterrupt:
            interrupted = True
            print("\ninterrupted", file=sys.stderr)
            break
        results.append(res)
        if not args.json:
            output.print_result(res, st, sys.stdout, args.verbose, args.links)
            sys.stdout.flush()

    as_json = json.dumps([output.to_dict(r) for r in results], indent=2)
    if args.json:
        print(as_json)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", errors="replace", newline="") as fh:
                if ext == ".json":
                    fh.write(as_json + "\n")
                elif ext == ".csv":
                    fh.write(output.to_csv(results))
                else:
                    for r in results:
                        output.print_result(r, output.Style(False), fh, args.verbose, args.links)
        except OSError as exc:
            print(f"cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
        if not args.json:
            print(f"[*] Saved to {args.output}")
    if interrupted:
        return 130
    return 1 if any(r.error for r in results) else 0
