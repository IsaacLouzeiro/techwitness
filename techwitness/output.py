"""Terminal, JSON and CSV output."""

import csv
import io
import itertools
import re

from . import __version__

LOGO = r"""
  _            _              _ _
 | |_ ___  ___| |____      __(_) |_ _ __   ___  ___ ___
 | __/ _ \/ __| '_ \ \ /\ / /| | __| '_ \ / _ \/ __/ __|
 | ||  __/ (__| | | \ V  V / | | |_| | | |  __/\__ \__ \
  \__\___|\___|_| |_|\_/\_/  |_|\__|_| |_|\___||___/___/
"""

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏ -‮⁦-⁩\ud800-\udfff]")


def safe(value):
    """Everything printed comes from the target: no escape sequences reach the terminal."""
    return _CONTROL.sub("?", str(value))


def _cut(text, n):
    text = safe(text)
    return text if len(text) <= n else text[:n - 3] + "..."


class Style:
    CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36"}

    def __init__(self, color):
        self.color = color

    def __call__(self, text, *names):
        text = safe(text)
        if not self.color:
            return text
        return f"\033[{';'.join(self.CODES[n] for n in names)}m{text}\033[0m"


def print_logo(st, out):
    out.write("\n".join(st(line, "cyan", "bold") for line in LOGO.split("\n")) + "\n")
    out.write(f"  techwitness v{__version__} - web technology fingerprinting\n\n")


def print_result(res, st, out, verbose=False, links=False):
    def w(line=""):
        out.write(line + "\n")

    info, good, bad = st("[*]", "blue"), st("[+]", "green"), st("[!]", "yellow")
    w("=" * 70)
    w(f"{info} Target: {st(res.target, 'bold')}")
    if res.error:
        w(f"{st('[-]', 'red')} {st(res.error, 'red')}\n")
        return
    for status, url in res.redirects:
        w(f"{info} Redirect: {status} {_cut(url, 120)}")
    w(f"{info} Effective URL: {st(res.url, 'cyan')}")
    w(f"{info} Status: {safe(f'{res.http_version} {res.status} {res.reason}')}")
    if res.title:
        w(f"{info} Title: {_cut(res.title, 100)}")
    if res.ip:
        w(f"{info} IP: {safe(res.ip)}")
    if res.tls:
        issuer = f", issued by {res.tls['issuer']}" if res.tls.get("issuer") else ""
        w(f"{info} TLS: {safe(res.tls['version'])} {safe(res.tls['cipher'])}{safe(issuer)}")
    if res.warning:
        w(f"{bad} {st(res.warning, 'yellow')}")
    w("=" * 70)

    w(f"\n{st('Banner', 'bold')}")
    for k, v in res.banner:
        w(f"{good} {st(k, 'cyan')}: {_cut(v, 120)}")
    for port, text in res.services:
        w(f"{good} {st(f'tcp/{port}', 'cyan')}: {_cut(text, 120) or '(open, no banner)'}")
    if not res.banner and not res.services:
        w("    nothing disclosed")

    w(f"\n{st('Technologies', 'bold')}")
    for category, group in itertools.groupby(res.technologies, key=lambda d: d.category):
        w(f"  {st(category, 'blue', 'bold')}")
        for d in group:
            line = f"    {good} {st(d.name, 'green')}"
            if d.version:
                line += " " + st(_cut(", ".join(d.version), 60), "yellow", "bold")
            if d.confidence < 100:
                line += st(f" ({d.confidence}%)", "dim")
            source = d.evidence[0]["source"] if d.evidence else "implied by " + ", ".join(d.implied_by)
            w(line + st(f"  <- {source}", "dim"))
            for e in d.evidence if verbose else ():
                w(st(f"          {e['source']}: {_cut(e['detail'], 110)}", "dim"))
                if e["url"]:
                    w(st(f"            at {_cut(e['url'], 110)}", "dim"))
    if not res.technologies:
        w("    none identified")

    _section(w, st, good, "Components", res.components, verbose)
    _section(w, st, good, "npm packages (source map)", res.packages, verbose)
    if res.leaks or res.comments:
        w(f"\n{st('Information disclosure', 'bold')}")
        for text in res.leaks:
            w(f"{bad} {_cut(text, 160)}")
        for text in res.comments if verbose else res.comments[:5]:
            w(f"{bad} HTML comment: {_cut(text, 120)}")
    if links:
        _section(w, st, good, "Internal links", res.internal_links, True)
        _section(w, st, good, "API endpoints in the code", res.endpoints, True)
        _section(w, st, good, "Subdomains", res.subdomains, True)
        _section(w, st, good, "Third-party hosts", res.external_hosts, True)

    w("\n" + "-" * 70)
    versions = sum(1 for d in res.technologies if d.version)
    w(f"{info} {st(len(res.technologies), 'bold')} technologies, {versions} with version")
    w(f"{info} {res.requests} requests, {res.pages} page(s), {res.scripts} script(s) analyzed")
    if not links and any((res.internal_links, res.endpoints, res.subdomains, res.external_hosts)):
        w(f"{info} {len(res.internal_links)} internal links, {len(res.endpoints)} API endpoints, "
          f"{len(res.subdomains)} subdomains, {len(res.external_hosts)} third-party hosts (--links to list)")
    w()


def _section(w, st, mark, title, items, full, limit=10):
    if not items:
        return
    w(f"\n{st(title, 'bold')}")
    for item in items if full else items[:limit]:
        w(f"{mark} {_cut(item, 160)}")
    if not full and len(items) > limit:
        w(f"    ... and {len(items) - limit} more (-v to list)")


def to_dict(res):
    d = dict(vars(res))
    d["redirects"] = [{"status": s, "url": u} for s, u in res.redirects]
    d["banner"] = [{"header": k, "value": v} for k, v in res.banner]
    d["services"] = [{"port": p, "banner": b} for p, b in res.services]
    d["technologies"] = [{"name": t.name, "category": t.category, "versions": t.version,
                          "confidence": t.confidence, "evidence": t.evidence, "implied_by": t.implied_by}
                         for t in res.technologies]
    return d


def _cell(value):
    """Spreadsheets run cells that start like a formula."""
    value = safe(value)
    return "'" + value if value[:1] in ("=", "+", "-", "@") else value


def to_csv(results):
    buf = io.StringIO()
    wr = csv.writer(buf, lineterminator="\n")
    wr.writerow(["target", "url", "category", "technology", "versions", "confidence", "evidence"])
    for res in results:
        for t in res.technologies:
            text = (f"{t.evidence[0]['source']}: {t.evidence[0]['detail']}" if t.evidence
                    else "implied by " + ", ".join(t.implied_by))
            wr.writerow([_cell(x) for x in (res.target, res.url, t.category, t.name, " ".join(t.version),
                                            t.confidence, text)])
    return buf.getvalue()
