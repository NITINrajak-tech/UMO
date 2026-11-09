# UMO

A small, local web app for learning basic vulnerability assessment. It checks one localhost or private-network host at a time, reports common open TCP ports, and makes a read-only HTTP `HEAD` request to inspect response headers and visible software-version hints.

## Run

Requires Python 3.10 or later. No third-party packages are needed.

```powershell
python app.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Stop the app with `Ctrl+C`.

## Use responsibly

Only scan systems you own or are explicitly authorized to assess. The scanner resolves and validates every target address and rejects public Internet addresses. It scans one host, uses a fixed list of common TCP ports, and does not exploit services, authenticate, crawl pages, or change the target. Port availability is only an observation; it is not proof of a vulnerability. Version checks are heuristics and should be verified against current vendor support information.

## Report

Use **Export report** to download the current findings as JSON. The report includes the target, scan time, resolved addresses, common open ports, response headers, severity counts, and the limitations of the check.