#!/usr/bin/env bash
# One-shot setup for Kali Linux
set -e
cd "$(dirname "$0")"

echo "[*] System packages..."
sudo apt update
sudo apt install -y python3 python3-venv python3-pip whois theharvester curl

echo "[*] Python virtualenv..."
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

if [ ! -f .env ]; then
  read -rp "Shodan API key paste karo (Enter = skip, free InternetDB use hoga): " k || true
  if [ -n "$k" ]; then
    echo "SHODAN_API_KEY=$k" > .env
    chmod 600 .env
  fi
fi

if ! command -v phoneinfoga >/dev/null 2>&1; then
  read -rp "PhoneInfoga install karu? (y/N): " a || true
  if [ "$a" = "y" ] || [ "$a" = "Y" ]; then
    bash <(curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install)
    sudo install ./phoneinfoga /usr/local/bin/phoneinfoga
  fi
fi

cat > osint <<'WRAP'
#!/usr/bin/env bash
D="$(dirname "$(readlink -f "$0")")"
exec "$D/.venv/bin/python" "$D/osint_aggregator.py" "$@"
WRAP
chmod +x osint

echo
echo "[+] Done. Try:  ./osint example.com"
