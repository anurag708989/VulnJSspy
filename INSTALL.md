# Installation Guide

## Requirements

- Python 3.7+ (3.11–3.13 tested)
- pip
- Optional: Go 1.21+ (only needed for domain-discovery tools)
- Optional: a Telegram bot token, if you want live alerts

## 1. Clone the repository

```bash
git clone https://github.com/<your-org>/vulnjspy-professional.git
cd vulnjspy-professional
```

## 2. Set up a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
```

## 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` contents:

```
rich>=13.0.0
aiohttp>=3.9.0
requests>=2.31.0
python-telegram-bot>=20.0
```

`python-telegram-bot` is optional — the tool detects its absence and simply disables
`--telegram-token`/`--chatid` support at runtime rather than erroring out.

## 4. Install discovery tools (required for `--domain` mode)

Domain scanning shells out to three Go-based tools. Install Go first if you don't have it:
[https://go.dev/doc/install](https://go.dev/doc/install)

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest
```

Make sure `$GOPATH/bin` (usually `~/go/bin`) is on your `PATH`:

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

Verify each tool resolves:

```bash
which gau httpx httprobe
```

`--file` and `--url` modes work without any of these — they only apply to `--domain` scans.

## 5. Verify the install

```bash
python3 vulnjspy.py --help-full
```

You should see the banner, methodology panel, and comparison table render in your terminal.

## Docker (optional)

A minimal Dockerfile for a self-contained environment:

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y golang-go git curl && rm -rf /var/lib/apt/lists/*

RUN go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/tomnomnom/httprobe@latest
ENV PATH="/root/go/bin:${PATH}"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENTRYPOINT ["python3", "vulnjspy.py"]
```

Build and run:

```bash
docker build -t vulnjspy .
docker run --rm -v $(pwd)/results:/app/vulnjspy_results vulnjspy --domain example.com
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: rich` | venv not activated or deps not installed | `source venv/bin/activate && pip install -r requirements.txt` |
| `--domain` scan finds 0 URLs | `gau`/`httpx` not on PATH | Re-check step 4, `which gau` |
| Telegram messages never arrive | Bot not started / wrong chat ID | Message your bot once first (Telegram requires the user to initiate), confirm chat ID with `@userinfobot` |
| Very slow domain scans | Too many workers for target rate limits | Lower `--workers`, raise `--timeout` |
| High false-positive rate on a specific target | Framework injects boilerplate matching a generic pattern | Add framework-specific junk values via `--exclude-words` |
