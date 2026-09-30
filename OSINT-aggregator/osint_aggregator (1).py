#!/usr/bin/env python3
"""
OSINT Aggregator v2
Aggregates PhoneInfoga, Shodan, WHOIS and theHarvester results into a structured
report (JSON + Markdown + HTML) for a phone number, email or domain.

Use ONLY on targets you own or are explicitly authorized to assess.
"""
import argparse
import html
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

EMAIL_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
PHONE_RE = re.compile(r"^\+\d{8,15}$")
DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")
DEFAULT_SOURCES = "crtsh,hackertarget,rapiddns,otx,urlscan,duckduckgo"
LINE_TYPES = {0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE", 3: "TOLL_FREE",
              4: "PREMIUM_RATE", 5: "SHARED_COST", 6: "VOIP", 7: "PERSONAL_NUMBER",
              8: "PAGER", 9: "UAN", 10: "VOICEMAIL", 99: "UNKNOWN"}


# ---------------------------------------------------------------- helpers
def detect_type(target):
    """Return (type, value). value = normalized phone / domain."""
    t = target.strip()
    if m := EMAIL_RE.match(t):
        return "email", m.group(1).lower()
    p = re.sub(r"[\s\-()]", "", t)
    if PHONE_RE.match(p):
        return "phone", p
    if DOMAIN_RE.match(t):
        return "domain", t.lower()
    raise ValueError(f"'{target}' valid phone (+countrycode...), email ya domain nahi hai")


def load_key(cli_key=None):
    if cli_key:
        return cli_key
    if os.getenv("SHODAN_API_KEY"):
        return os.getenv("SHODAN_API_KEY")
    for env in (Path(".env"), Path(__file__).resolve().parent / ".env"):
        if env.exists():
            for line in env.read_text().splitlines():
                m = re.match(r"\s*SHODAN_API_KEY\s*=\s*['\"]?([^'\"\s]+)", line)
                if m:
                    return m.group(1)
    return None


def run_cmd(cmd, timeout=180, cwd=None):
    if not shutil.which(cmd[0]):
        return {"error": f"{cmd[0]} not installed / not in PATH"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {"stdout": p.stdout.strip(), "stderr": p.stderr.strip(), "code": p.returncode}
    except subprocess.TimeoutExpired:
        return {"error": f"timeout after {timeout}s"}


def jsonable(v):
    if isinstance(v, (list, tuple, set)):
        return [jsonable(i) for i in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


# ---------------------------------------------------------------- modules
def whois_lookup(domain):
    keep = ("domain_name", "registrar", "creation_date", "expiration_date", "updated_date",
            "name_servers", "status", "emails", "org", "country", "dnssec")
    try:
        import whois  # python-whois
        w = dict(whois.whois(domain))
        return {k: jsonable(w[k]) for k in keep if w.get(k)}
    except Exception as e:
        raw = run_cmd(["whois", domain], timeout=30)
        raw["note"] = f"python-whois failed ({e}); CLI fallback used"
        return raw


def internetdb(ip):
    """Free, keyless Shodan InternetDB (ports, CPEs, hostnames, vulns)."""
    try:
        with urllib.request.urlopen(f"https://internetdb.shodan.io/{ip}", timeout=15) as r:
            d = json.load(r)
        return {"ip": ip, "source": "internetdb", "ports": d.get("ports", []),
                "hostnames": d.get("hostnames", []), "vulns": d.get("vulns", []),
                "cpes": d.get("cpes", []), "tags": d.get("tags", [])}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"ip": ip, "source": "internetdb", "note": "no data for this IP"}
        return {"ip": ip, "error": f"InternetDB HTTP {e.code}"}
    except Exception as e:
        return {"ip": ip, "error": f"InternetDB: {e}"}


def shodan_lookup(domain, key):
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
    except socket.gaierror as e:
        return {"error": f"DNS resolve failed: {e}"}
    api = None
    if key:
        try:
            import shodan
            api = shodan.Shodan(key)
        except ImportError:
            pass
    hosts = []
    for ip in ips:
        if api:
            try:
                h = api.host(ip)
                hosts.append({
                    "ip": ip, "source": "shodan-api", "org": h.get("org"), "isp": h.get("isp"),
                    "os": h.get("os"), "country": h.get("country_name"),
                    "hostnames": h.get("hostnames"), "ports": h.get("ports"),
                    "vulns": h.get("vulns", []),
                    "services": [{"port": s.get("port"), "product": s.get("product"),
                                  "version": s.get("version")} for s in h.get("data", [])],
                })
                continue
            except Exception as e:  # APIError, invalid key, no info for IP...
                fallback = internetdb(ip)
                fallback["api_note"] = str(e)
                hosts.append(fallback)
                continue
        hosts.append(internetdb(ip))
    out = {"mode": "api" if api else "internetdb (no API key)", "hosts": hosts}
    return out


def harvester_lookup(domain, sources, timeout):
    binary = shutil.which("theHarvester") or shutil.which("theharvester")
    if not binary:
        return {"error": "theHarvester not installed (sudo apt install theharvester)"}
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "harvest")
        res = run_cmd([binary, "-d", domain, "-b", sources, "-f", base], timeout=timeout, cwd=tmp)
        if "error" in res:
            return res
        jf = base + ".json"
        if os.path.exists(jf):
            with open(jf) as f:
                data = json.load(f)
            return {k: data.get(k, []) for k in ("emails", "hosts", "ips", "asns", "interesting_urls")}
        return {"note": "theHarvester ne JSON output nahi diya", "stdout_tail": res.get("stdout", "")[-1500:],
                "stderr_tail": res.get("stderr", "")[-800:]}


def parse_kv(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9 _/]+?):\s+(.+)$", line)
        if not m:
            continue
        k, v = m.group(1).strip(), m.group(2).strip()
        if k in d:
            d[k] = d[k] if isinstance(d[k], list) else [d[k]]
            d[k].append(v)
        else:
            d[k] = v
    return d


def phone_lookup(number):
    out = {}
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as tz
        n = phonenumbers.parse(number, None)
        out["phonenumbers"] = {
            "valid": phonenumbers.is_valid_number(n),
            "possible": phonenumbers.is_possible_number(n),
            "e164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "country_code": n.country_code,
            "region": phonenumbers.region_code_for_number(n),
            "location": geocoder.description_for_number(n, "en"),
            "carrier": carrier.name_for_number(n, "en"),
            "timezones": list(tz.time_zones_for_number(n)),
            "line_type": LINE_TYPES.get(phonenumbers.number_type(n), "UNKNOWN"),
        }
    except ImportError:
        out["phonenumbers"] = {"error": "pip install phonenumbers"}
    except Exception as e:
        out["phonenumbers"] = {"error": str(e)}
    pi = run_cmd(["phoneinfoga", "scan", "-n", number], timeout=120)
    if "error" in pi:
        out["phoneinfoga"] = pi
    else:
        out["phoneinfoga"] = {"parsed": parse_kv(pi["stdout"]), "raw": pi["stdout"],
                              "stderr": pi["stderr"][-500:]}
    return out


# ---------------------------------------------------------------- report
def summarize(r):
    s = {}
    w = r.get("WHOIS")
    if isinstance(w, dict):
        for k in ("registrar", "creation_date", "expiration_date", "org", "country"):
            if w.get(k):
                s[k] = w[k]
    sh = r.get("Shodan")
    hosts = sh.get("hosts", []) if isinstance(sh, dict) else []
    if hosts:
        s["ips"] = [h.get("ip") for h in hosts]
        s["open_ports"] = sorted({p for h in hosts for p in (h.get("ports") or [])})
        s["vulns"] = sorted({v for h in hosts for v in (h.get("vulns") or [])})
        s["shodan_mode"] = sh.get("mode")
    th = r.get("theHarvester")
    if isinstance(th, dict) and "error" not in th:
        s["emails_found"] = len(th.get("emails") or [])
        s["hosts_found"] = len(th.get("hosts") or [])
    ph = r.get("Phone")
    if isinstance(ph, dict) and isinstance(ph.get("phonenumbers"), dict):
        for k in ("valid", "region", "location", "carrier", "line_type"):
            if k in ph["phonenumbers"]:
                s[k] = ph["phonenumbers"][k]
    return s


def find_errors(r):
    errs = []

    def walk(name, v):
        if isinstance(v, dict):
            if "error" in v:
                errs.append(f"{name}: {v['error']}")
            for k, x in v.items():
                if isinstance(x, (dict, list)):
                    walk(f"{name}.{k}", x)
        elif isinstance(v, list):
            for i in v:
                walk(name, i)
    for k, v in r.items():
        walk(k, v)
    return errs


def to_markdown(rep):
    L = [f"# OSINT Report: `{rep['target']}`", f"- Type: **{rep['type']}**",
         f"- Generated (UTC): {rep['generated_utc']}", "", "## Summary"]
    for k, v in rep["summary"].items():
        L.append(f"- **{k}**: {v}")
    if rep["errors"]:
        L += ["", "## Warnings"] + [f"- {e}" for e in rep["errors"]]
    for sec, data in rep["results"].items():
        L += ["", f"## {sec}", "```json", json.dumps(data, indent=2, default=str), "```"]
    return "\n".join(L) + "\n"


def to_html(rep):
    e = html.escape
    rows = "".join(f"<tr><th>{e(str(k))}</th><td>{e(str(v))}</td></tr>" for k, v in rep["summary"].items())
    warns = "".join(f"<li>{e(w)}</li>" for w in rep["errors"])
    secs = "".join(f"<h2>{e(n)}</h2><pre>{e(json.dumps(d, indent=2, default=str))}</pre>"
                   for n, d in rep["results"].items())
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT: {e(rep['target'])}</title>
<style>body{{font-family:system-ui,sans-serif;background:#0f1419;color:#e6e6e6;max-width:900px;margin:auto;padding:16px}}
h1,h2{{color:#4fc3f7}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #2a3340;padding:6px 10px;text-align:left;vertical-align:top}}
th{{width:30%;background:#18202a}}pre{{background:#18202a;padding:12px;overflow-x:auto;border-radius:6px}}.warn{{color:#ffb74d}}</style></head><body>
<h1>OSINT Report: {e(rep['target'])}</h1><p>Type: <b>{e(rep['type'])}</b> | Generated (UTC): {e(rep['generated_utc'])}</p>
<h2>Summary</h2><table>{rows}</table>
{'<h2 class="warn">Warnings</h2><ul class="warn">' + warns + '</ul>' if warns else ''}
{secs}</body></html>"""


# ---------------------------------------------------------------- main
def investigate(target, args, key):
    ttype, value = detect_type(target)
    jobs = {}
    if ttype == "phone":
        jobs["Phone"] = lambda: phone_lookup(value)
    else:
        jobs["WHOIS"] = lambda: whois_lookup(value)
        jobs["Shodan"] = lambda: shodan_lookup(value, key)
        jobs["theHarvester"] = lambda: harvester_lookup(value, args.sources, args.timeout)
    jobs = {k: f for k, f in jobs.items() if k.lower() not in args.skip}

    results = {}
    with ThreadPoolExecutor(max_workers=len(jobs) or 1) as ex:
        futs = {}
        for name, fn in jobs.items():
            print(f"[*] {name} started...")
            futs[name] = ex.submit(fn)
        for name, fut in futs.items():
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"error": f"unhandled: {e}"}
            print(f"[+] {name} done")

    if ttype == "email" and isinstance(results.get("theHarvester"), dict):
        seen = [x.lower() for x in results["theHarvester"].get("emails", []) or []]
        results["Email check"] = {"email": target.lower(), "seen_in_harvest": target.lower() in seen,
                                  "domain_analysed": value}

    rep = {"target": target, "type": ttype,
           "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "results": results}
    rep["summary"] = summarize(results)
    rep["errors"] = find_errors(results)
    return rep


def save(rep, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", rep["target"]) + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    (outdir / f"{stem}.json").write_text(json.dumps(rep, indent=2, default=str))
    (outdir / f"{stem}.md").write_text(to_markdown(rep))
    (outdir / f"{stem}.html").write_text(to_html(rep))
    return outdir / stem


def main():
    ap = argparse.ArgumentParser(description="OSINT aggregator: phone / email / domain -> report")
    ap.add_argument("targets", nargs="*", help="phone (+91...), email or domain")
    ap.add_argument("-f", "--file", help="text file, ek line mein ek target")
    ap.add_argument("-o", "--outdir", default="reports")
    ap.add_argument("-k", "--key", help="Shodan API key (ya SHODAN_API_KEY env / .env file)")
    ap.add_argument("-s", "--sources", default=DEFAULT_SOURCES, help="theHarvester sources")
    ap.add_argument("-t", "--timeout", type=int, default=300, help="theHarvester timeout (sec)")
    ap.add_argument("--skip", nargs="*", default=[], choices=["whois", "shodan", "theharvester", "phone"],
                    help="modules skip karo")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        targets += [l.strip() for l in Path(args.file).read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("kam se kam ek target do")

    key = load_key(args.key)
    print("[i] Shodan mode:", "API key found" if key else "no key -> free InternetDB fallback")
    for t in targets:
        print(f"\n=== {t} ===")
        try:
            rep = investigate(t, args, key)
        except ValueError as e:
            print(f"[!] {e}")
            continue
        path = save(rep, Path(args.outdir))
        print(f"[+] Reports: {path}.json | .md | .html")
        for w in rep["errors"]:
            print(f"[!] {w}")


if __name__ == "__main__":
    main()
