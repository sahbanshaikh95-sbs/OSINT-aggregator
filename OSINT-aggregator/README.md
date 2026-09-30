# OSINT Aggregator

Aggregates **PhoneInfoga, Shodan, WHOIS and theHarvester** results into a structured
report (JSON + Markdown + HTML) for any phone number, email or domain.

> **Legal / ethical use only.** Run this only against targets you own or have
> written authorization to assess. Phone/email lookups can involve personal data.

## Setup (Kali Linux)

```bash
chmod +x setup.sh && ./setup.sh
```

This installs `theharvester` and `whois`, creates a virtualenv, installs Python deps,
saves your Shodan key to `.env`, optionally installs PhoneInfoga, and creates the `./osint` launcher.

## Shodan API key

1. Register at https://account.shodan.io/register
2. Copy the key from https://account.shodan.io
3. Provide it via any one of: `.env` file (`SHODAN_API_KEY=...`), `export SHODAN_API_KEY=...`, or `-k KEY`

No key? The tool falls back to Shodan's free keyless **InternetDB** (ports, CPEs, hostnames, CVEs).

## Usage

```bash
./osint example.com                    # domain
./osint someone@example.com            # email (analyses its domain)
./osint +919876543210                  # phone (include country code)
./osint example.com +14155550100       # multiple targets
./osint -f targets.txt                 # targets from file
./osint example.com --skip theharvester   # skip a slow module
./osint example.com -s crtsh,hackertarget # choose theHarvester sources
```

Reports land in `reports/<target>_<timestamp>.{json,md,html}`.

## What each module does

| Module | Used for | Notes |
|---|---|---|
| WHOIS | domain / email | registrar, dates, nameservers |
| Shodan | domain / email | DNS -> IPs -> ports, services, CVEs |
| theHarvester | domain / email | emails, subdomains, IPs |
| PhoneInfoga + `phonenumbers` | phone | carrier, region, line type, scan output |

If a tool is missing, its section shows an `error` and the rest of the report still generates.
