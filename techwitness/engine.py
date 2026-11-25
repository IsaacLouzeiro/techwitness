"""Matches the signatures against what was collected and adds up the results."""

from dataclasses import dataclass, field

from .signatures import SIGNATURES

MIN_CONFIDENCE = 50


@dataclass
class Detection:
    name: str
    category: str
    confidence: int = 0
    versions: dict = field(default_factory=dict)    # version -> times seen
    evidence: list = field(default_factory=list)    # {source, detail, url}
    implied_by: list = field(default_factory=list)
    seen: set = field(default_factory=set)

    @property
    def version(self):
        """All versions seen, most frequent first (two copies of a library do happen)."""
        order = sorted(self.versions, key=lambda v: -self.versions[v])
        # "1.18" next to "1.18.0" is the same thing with less detail
        return [v for v in order if not any(o != v and o.startswith(v + ".") for o in order)]


class Engine:
    def __init__(self, signatures=None):
        self.signatures = SIGNATURES if signatures is None else signatures
        self.found = {}
        self.by_npm = {n: s.name for s in self.signatures.values() for n in s.npm}
        self.by_name = {_norm(n): n for n in self.signatures}
        # index by kind so each text only meets the rules that concern it
        self.rules, self.dict_rules = {}, {}
        for sig in self.signatures.values():
            for kind, value in sig.rules.items():
                if isinstance(value, dict):
                    for key, pattern in value.items():
                        self.dict_rules.setdefault((kind, key), []).append((sig, pattern))
                else:
                    self.rules.setdefault(kind, []).extend((sig, p) for p in value)

    def add(self, name, source, detail, url="", version=None, confidence=100, rule=None):
        d = self.found.setdefault(name, Detection(name, self.signatures[name].category))
        # the same rule matching on ten pages is still one piece of evidence
        key = rule if rule is not None else (source, detail)
        if key not in d.seen:
            d.seen.add(key)
            d.confidence = min(100, d.confidence + confidence)
            d.evidence.append({"source": source, "detail": detail[:160], "url": url})
        version = (version or "").strip(" .-_")
        if version:
            d.versions[version] = d.versions.get(version, 0) + 1

    def match(self, kind, text, url="", label=None):
        """Text-like kinds: html, js, script, asset, css, cookie, error, robots, cert, banner."""
        for sig, p in self.rules.get(kind, ()):
            m = p.regex.fullmatch(text) if kind == "cookie" else p.regex.search(text)
            if m:
                self._hit(sig, p, m, label or kind, text if len(text) <= 160 else m.group(0), url)

    def match_pair(self, kind, key, value, url=""):
        """header and meta."""
        for sig, p in self.dict_rules.get((kind, key.lower()), ()):
            m = p.regex.search(value)
            if m:
                self._hit(sig, p, m, kind, f"{key}: {value}", url)

    def match_probe(self, sig, pattern, text, url):
        m = pattern.regex.search(text)
        if m:
            self._hit(sig, pattern, m, "probe", m.group(0), url)

    def _hit(self, sig, p, m, source, detail, url):
        version = next((g for g in m.groups() if g), None)
        self.add(sig.name, source, " ".join(detail.split()), url, version, p.confidence, rule=id(p))

    def add_npm(self, package, url):
        name = self.by_npm.get(package)
        if name:
            self.add(name, "source map", package, url)
        return bool(name)

    def add_license(self, name, version, url):
        """Licence comment in a JS file: only trusted when the library is a known one."""
        base = _norm(name)
        known = (self.by_npm.get(name.lower()) or self.by_name.get(base)
                 or self.by_name.get(base.removesuffix("js")))
        if known:
            self.add(known, "license comment", f"{name} {version}", url, version)
        return bool(known)

    def results(self):
        # resolve implied technologies, transitively, from what passed the cut
        queue = [d.name for d in self.found.values() if d.confidence >= MIN_CONFIDENCE]
        done = set()
        while queue:
            name = queue.pop()
            if name in done:
                continue
            done.add(name)
            for other in self.signatures[name].implies:
                o = self.found.setdefault(other, Detection(other, self.signatures[other].category))
                if name not in o.implied_by:
                    o.implied_by.append(name)
                o.confidence = max(o.confidence, self.found[name].confidence)
                queue.append(other)
        out = [d for d in self.found.values() if d.confidence >= MIN_CONFIDENCE]
        return sorted(out, key=lambda d: (d.category.lower(), d.name.lower()))


def _norm(text):
    return "".join(c for c in text.lower() if c.isalnum())
