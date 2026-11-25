# techwitness

[![PyPI](https://img.shields.io/pypi/v/techwitness)](https://pypi.org/project/techwitness/)
[![Python](https://img.shields.io/pypi/pyversions/techwitness)](https://pypi.org/project/techwitness/)
[![Tests](https://github.com/IsaacLouzeiro/techwitness/actions/workflows/tests.yml/badge.svg)](https://github.com/IsaacLouzeiro/techwitness/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/IsaacLouzeiro/techwitness/blob/main/LICENSE)

Identifies the technologies behind a website, with versions and **the evidence for each one**, straight in the terminal. Python standard library only.

| Source | What it gives |
|---|---|
| HTTP banner | `Server`, `X-Powered-By` and other headers, cookies, every redirect |
| TLS | protocol, cipher, certificate issuer, subdomains in the certificate |
| HTML | meta tags, markup, comments, forms |
| Links | crawls the site; scripts, styles, third-party hosts, subdomains |
| JavaScript | inline code and downloaded files: frameworks, licence comments, API endpoints |
| Error page and robots.txt | what the server reveals in a 404 |
| Source maps (`-a 3`) | npm packages bundled in the site |
| Known paths (`-a 3`) | `/wp-login.php`, `/actuator`, `/swagger/`, version files... |
| TCP banners (`-b`) | SSH, FTP, SMTP, POP3, IMAP, MySQL, Redis |

## Installation

Requires Python 3.10+.

```bash
pipx install techwitness      # or: pip install techwitness
```

Or from source, with nothing to install:

```bash
git clone https://github.com/IsaacLouzeiro/techwitness.git
cd techwitness
python3 -m techwitness --help
```

## Usage

```bash
techwitness target.com
techwitness target.com -v                 # all the evidence
techwitness target.com -l                 # links, endpoints, subdomains, third-party hosts
techwitness target.com -a 1               # first page only
techwitness target.com -a 3               # also known paths and source maps
techwitness target.com -b                 # also TCP banners
techwitness target.com -p 22,2222         # TCP banners of these ports
techwitness -f targets.txt -o result.csv  # .json, .csv or .txt
techwitness target.com -j                 # JSON on stdout
techwitness target.com -x http://127.0.0.1:8080 -c 'session=...'
```

Without a scheme, https is tried first and then http.

```
======================================================================
[*] Target: scanme.nmap.org
[*] Effective URL: http://scanme.nmap.org/
[*] Status: HTTP/1.1 200 OK
[*] Title: Go ahead and ScanMe!
======================================================================

Banner
[+] Server: Apache/2.4.7 (Ubuntu)
[+] tcp/22: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13

Technologies
  Network service
    [+] OpenSSH 6.6.1p1  <- banner tcp/22
  Operating system
    [+] Ubuntu  <- header
  Web server
    [+] Apache HTTP Server 2.4.7  <- header

Information disclosure
[!] Version in response header: Server: Apache/2.4.7 (Ubuntu)
```

## How it behaves

- Weak evidence has a lower confidence and adds up; below 50% it is not reported.
- Crawling stays on the target host and skips links such as logout or delete. Scripts are only downloaded from the target's own domain; third-party ones are identified by URL.
- `-H` and `-c` values are only sent to the target host (and its `www` variant), never to a redirect elsewhere.
- Invalid certificates are reported and the scan goes on.
- Text from the target is stripped of terminal escape sequences before being printed.

Limitations: pages are not rendered in a browser, so what only appears after JavaScript runs can be missed; HTTP/2 is not used.

## Adding a technology

Signatures are in [`techwitness/signatures.py`](https://github.com/IsaacLouzeiro/techwitness/blob/main/techwitness/signatures.py); the fields are described at the top of the file:

```python
T("Ghost", "CMS", implies=["Node.js"], meta={"generator": r"^Ghost ?([\d.]+)?"})
```

## Tests

```bash
python -m unittest discover tests -v
```

## Legal

Only scan systems you own or are authorized to test.
