# Xpl01ts File Scanner

A Python-based file and directory scanner that checks files for suspicious activity using multiple detection engines.

It combines findings into a risk score (0–100) to help identify potentially malicious files.

## Features

- **File scanning** – Scan individual files or entire directories.
- **Real-time monitoring** – Watch folders for new or modified files.
- **Multiple detection engines** – Hash analysis, entropy, PE analysis, signatures and file forensics.
- **Malware database** – Check files against locally stored malware hashes.
- **ClamAV & YARA** – Support for local ClamAV signatures and custom YARA rules.
- **VirusTotal** – Optional hash lookups and file uploads.
- **Risk scoring** – Assigns each file a score from 0–100.
- **Quarantine** – Move suspicious files and restore them when needed.
- **Reports** – Export results as HTML, TXT, JSON, CSV or Markdown.

## Risk Levels

| Score | Verdict |
| --- | --- |
| 0–4 | CLEAN |
| 5–19 | LOW |
| 20–44 | MEDIUM |
| 45–69 | HIGH |
| 70–100 | CRITICAL |

## Installation

**Requirements:** Python 3.10+

1. Copy the project files into a folder.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the scanner:

```bash
python scanner.py
```

You can also use menu option `9` to check and install missing dependencies.

## VirusTotal (Optional)

Set your API key before launching:

```powershell
$env:VT_API_KEY = "your-api-key"
```

Linux / macOS:

```bash
export VT_API_KEY="your-api-key"
```

## Data Storage

Scanner data is stored next to `scanner.py` when possible.

| File / Folder | Purpose |
| --- | --- |
| `quarantine/` | Quarantined files |
| `reports/` | Saved scan reports |
| `malware_hashes.json` | Local malware hash database |
| `scan_history.json` | Recent scan history |
| `scanner.log` | Scanner logs |
| `scanner_crash.log` | Crash information |
| `yara_rules/` | Custom YARA rules |

## Notes

- Files larger than 500 MB are skipped.
- Content-based analysis reads up to 64 MB per file.
- Some detections may produce false positives.
- A CLEAN result does not guarantee that a file is safe.

## Disclaimer

For personal and educational use only. Only scan files you own or have permission to analyse.

This scanner is not a replacement for antivirus software. Its an additional scanner used in projects! For checking files.
