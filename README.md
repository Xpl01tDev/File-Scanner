# Xpl01ts File Scanner

A Python file and directory scanner that runs every file through several independent detection engines and folds all of their signals into one 0–100 risk score. It is built to catch the whole range of suspicious files — packed executables, macro documents, zip bombs, ransomware-style scripts — using local heuristics first and external engines only if you have them.

It is fully interactive: start it and everything happens from a menu. No arguments to remember, no flags to look up. The screen clears and redraws the banner after every task, so it always drops you back at the menu.

```powershell
.\scanner.exe
```

From source instead (any platform), it is `python scanner.py` — otherwise identical.

```
██╗  ██╗██████╗ ██╗      ██████╗  ██╗████████╗███████╗    ███████╗██╗██╗     ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
╚██╗██╔╝██╔══██╗██║     ██╔═████╗███║╚══██╔══╝██╔════╝    ██╔════╝██║██║     ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ╚███╔╝ ██████╔╝██║     ██║██╔██║╚██║   ██║   ███████╗    █████╗  ██║██║     █████╗      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔██╗ ██╔═══╝ ██║     ████╔╝██║ ██║   ██║   ╚════██║    ██╔══╝  ██║██║     ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██╔╝ ██╗██║     ███████╗╚██████╔╝ ██║   ██║   ███████║    ██║     ██║███████╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
  hash-DB: 0 hashes  |  engines: heuristics, file-forensics

  MAIN MENU   hash-DB: 0 entries
────────────────────────────────────────────────────────────────────────────
   1)  Scan a file or folder
   2)  Watch a folder in real time
   3)  Hash / fingerprint a single file
   4)  Export a report from a saved scan
   5)  Quarantine manager (list / restore / purge)
   6)  Recent scans
   7)  Show detection rules & engines
   d)  Diagnostics (engines, paths, import problems)
   8)  Malware hash database
   9)  Check / install dependencies
   s)  Settings (screen clearing, export defaults)
   q)  Quit
────────────────────────────────────────────────────────────────────────────
```

## Contents

- [How it works](#how-it-works)
- [Detection engines](#detection-engines)
- [Risk scoring](#risk-scoring)
- [The menu](#the-menu)
- [Reports and export](#reports-and-export)
- [Quarantine](#quarantine)
- [What gets written to disk](#what-gets-written-to-disk)
- [Install](#install)
- [Windows notes](#windows-notes)
- [Performance and limits](#performance-and-limits)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

## How it works

Every file is opened once (up to 64 MB is held in memory so the content engines do not have to re-read it) and pushed through the engines below. Each engine only adds evidence; the final verdict comes from the weighted score, never from a single rule in isolation.

Two deliberate design choices keep it from being useless noise:

- **Self-awareness.** Matches inside comments, inside the pattern tables themselves, or inside a file that looks like detection tooling are ignored, so the scanner does not flag itself, other scanners, or rule definition files.
- **Content over extension.** Text-versus-binary is decided by sniffing the bytes, not by trusting the file name, and a file claiming to be a PDF while carrying an `MZ` header is reported rather than treated as a document.

## Detection engines

| Engine | Needs a service? | What it contributes |
| --- | --- | --- |
| Hashes | no | MD5, SHA1, SHA256, SHA512 plus lookup against the local malware hash database |
| Entropy | no | 4 KB window entropy, high-entropy chunks, average, max, **and** near-empty padded chunks |
| Magic / MIME | no | type detection from magic bytes, with libmagic when available |
| PE analysis | no | 32/64-bit, section table, executable+writable sections, size ratios, compile timestamp, imported DLLs and functions |
| Behaviour analysis | no | 37 patterns across source and script types, weighted by category |
| Signature rules | no | 36 regex rules for high-confidence combinations |
| File forensics | no | container and document format checks (below) |
| ClamAV signatures | no | offline matching against a local ClamAV `.ndb` / `.hdb` / `.hsb` database |
| ClamAV daemon / CLI | yes | verdict from `clamd` or `clamscan` when present |
| YARA | no | any rules you drop into `yara_rules/`, if `yara-python` loads |
| VirusTotal | yes | hash reputation, optionally a full file upload |

### Hashes

All four digests are computed in one streaming pass and shown for every file, so you can paste a SHA256 straight into VirusTotal or a threat-intel feed. Files found in the local hash database short-circuit to **CRITICAL 100**.

### Entropy

Uniformly high entropy across a file is the classic tell for packed, compressed or encrypted payloads. This scanner looks at three things:

- whole-file entropy and the 4 KB-window average and maximum
- the ratio of high-entropy chunks (above 7.0 and 7.5)
- **padded chunks** — runs of near-zero entropy. Malware that pads itself with zeroes to drag its average entropy down is detected instead of slipping through.

### PE analysis

Windows executables get the header walked properly: architecture, every section with its virtual/raw sizes and the EXEC/WRITE flags, the compile timestamp, and the import directory resolved to actual DLL and function names. Packer section names (`UPX0`, `.themida`, `.vmp1`, …), write+execute sections, extreme virtual-to-raw ratios, a compile timestamp in the future, and imports like `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread` / `CryptEncrypt` / `URLDownloadToFile` all raise the score.

### Behaviour analysis

For source and script files (Python, JavaScript, PowerShell, batch, shell, PHP, VBS, HTA, and more) the content is matched against a library of behavioural patterns: ransomware notes, decryption demands and ransom payment language, mass file encryption, file system destruction, shadow-copy deletion, AMSI/ETW bypass, anti-VM and anti-debug checks, keylogging hooks, process injection, credential dumping, C2 and webhook exfiltration, screenshot capture, persistence and watchdog respawn, system fingerprinting, AV tampering, and offensive-security tooling.

Findings are grouped into categories (ransomware, destruction, evasion, exfiltration, persistence, surveillance, process execution, encryption, file access, network, reconnaissance, system modification, offensive tooling) and risky combinations score extra — ransomware + persistence + exfiltration together is a much stronger signal than any one of them alone.

### Signature rules

Thirty-six regex rules for higher-confidence combinations, including reverse shells, registry run-key persistence, Discord and Telegram exfiltration, browser and crypto-wallet credential theft, clipboard hijacking, scheduled-task and service persistence, LOLBin downloads, process injection APIs, keylogger APIs, shellcode byte runs, PDF JavaScript auto-actions, VBA autorun macros, mshta/regsvr32/rundll32 abuse, wall-paper hijacking, multi-monitor UI locks and ransom-extension renames.

### File forensics

Container and document checks that never extract or execute anything:

- **Archive bombs** — entry count, uncompressed size and compression ratio, flagged above 200× to more than 50 MB or any ratio above 1000×
- **Zip slip** — entries containing `../`, absolute paths or drive letters
- **Executables inside archives** — `.exe`, `.dll`, `.scr`, `.js`, `.vbs`, `.ps1`, `.bat`, `.hta`, `.lnk`, `.jar` payloads
- **Double extensions** — `invoice.pdf.exe`, `photo.jpg.scr` (CRITICAL when the real type is executable)
- **Extension / content mismatch** — a PDF that is really a PE, a `.txt` full of binary, a truncated or polyglot PDF
- **PDF** — `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile`, `/OpenAction`, `/AA`, `/RichMedia`, `/XFA`
- **Office** — `vbaProject.bin`, OLE macro streams, `AutoOpen`, `Document_Open`, `Workbook_Open`
- **RTF** — `\objdata` and embedded OLE objects
- **LNK** — shortcuts that launch a scripting host
- Encrypted archive entries and password-protected malspam attachments

### ClamAV signature database

If ClamAV is installed, its local signature files in `/var/lib/clamav`, `/usr/local/share/clamav`, `/var/db/clamav` (or a `clamav/` folder next to the script) are parsed directly. `.hdb`/`.hsb` hashes and plain hex `.ndb` patterns are matched in-process, so you get ClamAV detection strength without a running daemon and without uploading anything.

### YARA

Drop `.yar` or `.yara` files into a `yara_rules/` folder beside the script and they are compiled once and applied. A rule's `severity` metadata (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`) drives its weight. If `yara-python` cannot load on your machine, the engine simply reports as unavailable instead of crashing the scanner.

## Risk scoring

Every signal feeds a weighted total from 0 to 100:

| Score | Level |
| --- | --- |
| 0–4 | CLEAN |
| 5–19 | LOW |
| 20–44 | MEDIUM |
| 45–69 | HIGH |
| 70–100 | CRITICAL |

Guarantees in the scoring logic:

- A local malware-hash match short-circuits straight to **CRITICAL 100**.
- A ClamAV infection, a CRITICAL ClamAV-database signature, or a CRITICAL signature/YARA rule can never be graded below **CRITICAL**, even when the total weights would otherwise land lower.
- Category combinations, finding counts and severity counts all add on top of the individual findings.

## The menu

**1 — Scan a file or folder.** Asks for a path, whether to do a quick scan (no VirusTotal, no ClamAV daemon, no network), and for folders whether to print one line per file and whether to descend into subfolders. Ends with a summary — per-level bars, a ranked list of everything flagged — then the export prompt.

**2 — Watch a folder in real time.** Choose the folder, whether to use VirusTotal, and whether to auto-quarantine anything scoring 75 or higher. New and changed files are debounced so a download that fires several filesystem events is only scanned once, and temp files (`.part`, `.crdownload`, `.tmp`, `~$…`) are ignored until they are finished.

**3 — Hash / fingerprint a single file.** Digests plus entropy and window statistics, and whether the file is already in your hash database. Copies the SHA256 to the clipboard if `pyperclip` is installed.

**4 — Export a report.** Pick a saved scan from `reports/`, or point it at any file or folder to scan first, then export.

**5 — Quarantine manager.** List quarantined files with their original location, timestamp, size and verdict, restore one to its original path (or anywhere you choose), or purge the lot.

**6 — Recent scans.** The last 200 scans with file counts, flagged counts and duration.

**7 — Detection rules & engines.** Prints every signature rule, every behaviour pattern and the list of active engines — useful for audits and for seeing exactly what a verdict means.

**d — Diagnostics.** Python and platform, executable, working directory and every data path, which engines are available, and the precise reason for each one that is not. This is the first place to look when something is missing.

**8 — Malware hash database.** Per-algorithm counts, and add a hash by hand.

**9 — Check / install dependencies.** Lists missing packages, offers to install them, and verifies afterwards.

**s — Settings.** Toggle screen clearing, change the default export format and folder for the session.

**q — Quit.**

## Reports and export

After any scan you are asked whether to export a report, and if so:

1. **Format** — `html`, `txt`, `json`, `csv` or `md`
2. **Contents** — only flagged files, per-file detail, hashes, and individual findings, each optional
3. **Name** — with a sensible default built from the target and the timestamp
4. **Folder** — defaults to `~/Documents/Xpl01ts File Scanner Reports`, with `~` and environment variables expanded

| Format | Best for |
| --- | --- |
| `html` | default — a single self-contained dark-theme report with verdict cards and severity chips, no external assets, opens anywhere |
| `txt` | plain-text reports for tickets, email or logs |
| `json` | full machine-readable data for scripting or archiving |
| `csv` | one row per finding with file, verdict, severity and context — opens in Excel or Sheets |
| `md` | markdown for a GitHub issue, wiki or PR comment |

Every report carries the scanner name, generation time, host, platform, target, per-level counts, severity totals, engines used, scan duration, the findings, and a short recommendations section that adapts to what was found.

If the chosen folder is not writable, the scanner says so and falls back to a safe default rather than losing the report. If a file with that name already exists, a timestamp is appended instead of overwriting it.

## Quarantine

Auto-quarantine moves anything scoring 75+ out of the watched folder into `quarantine/` and records the original path, time, verdict, size and SHA256 in `quarantine/manifest.json`. Nothing is silently destroyed: you can list, restore or purge from menu option 5.

## What gets written to disk

Everything lives beside the script when that folder is writable, otherwise in a per-user data directory:

Paths are relative to the folder containing `scanner.exe` (or `scanner.py`), with an automatic fallback to `%LOCALAPPDATA%\Xpl01tsFileScanner` on Windows when that folder is read-only — option **d** in the menu shows the resolved location.

| Path | Purpose |
| --- | --- |
| `quarantine/` | quarantined files and `manifest.json` |
| `reports/` | automatic JSON scan reports |
| `malware_hashes.json` | local known-malware hash database |
| `scan_history.json` | last 200 scans |
| `scanner.log` | engine-level log |
| `scanner_crash.log` | only written when something unexpected happens |
| `yara_rules/` | optional, your YARA rules |

## Install

### Windows executable (no Python needed)

1. Download the latest `scanner.exe` from Releases.
2. Put it in its own folder, for example `C:\Tools\Xpl01ts\`.
3. Open a terminal in that folder and start it:

   ```powershell
   cd C:\Tools\Xpl01ts
   .\scanner.exe
   ```

   **Start it from a terminal.** Opening it by double-clicking in Explorer does not work — it has no terminal to draw into, so the window closes immediately. It reads its input and prints its output to the console, so it needs one. PowerShell, Windows Terminal, cmd and VS Code's terminal all work; navigate to the folder first, then run `.\scanner.exe`.

   No install step, no dependencies, nothing to configure.

The executable keeps its data next to itself: `quarantine\`, `reports\`, `malware_hashes.json`, `scanner.log`. If it sits somewhere it cannot write to (for example `C:\Program Files` without rights), it automatically uses `%LOCALAPPDATA%\Xpl01tsFileScanner` instead — menu option **d** shows which path is in use.

Windows may warn on first launch because the exe is unsigned. Choose *More info → Run anyway*, or verify the download against the SHA256 on the Releases page.

### From source (Windows, Linux, macOS)

Requires **Python 3.10 or newer**.

```bash
git clone <your-repo-url>
cd <repo>
python -m venv .venv
```

Activate it — Windows: `.venv\Scripts\activate`, Linux/macOS: `source .venv/bin/activate` — then:

```bash
pip install -r requirements.txt
python scanner.py
```

Menu option 9 does the same thing from inside the program and tells you exactly which packages are missing.

`requirements.txt` covers the optional engines. Everything in it is genuinely optional — the scanner starts and scans with nothing but the standard library, and reports the missing engines as unavailable.

### VirusTotal (optional, both installs)

Set an API key before starting:

```powershell
$env:VT_API_KEY = "..."     # Windows PowerShell
set VT_API_KEY=...          # Windows cmd
export VT_API_KEY=...       # Linux / macOS
```

VirusTotal is only used when you leave it enabled on a non-quick scan; local heuristics, forensics, signature rules and ClamAV database matching never touch the network.

## Windows notes

- Runs as `scanner.exe` with no Python installed, but it must be launched from a terminal (`cd` to its folder, then `.\scanner.exe`). Double-clicking in Explorer closes the window instantly because there is no console attached, so that is not a supported way to start it.
- SmartScreen may ask for confirmation on an unsigned exe; *More info → Run anyway*. Sign the binary to remove the prompt.
- To build the exe yourself:

  ```powershell
  pip install -r requirements.txt pyinstaller
  pyinstaller --onefile --console --name scanner --collect-all yara --collect-all magic scanner.py
  ```

  The `--collect-all` flags bundle the YARA and libmagic data files; drop either one if you do not want that engine.
- The file picker accepts `C:\Users\you\Downloads`, `~/Downloads` or a plain relative path.
- `python-magic` needs a DLL on Windows, so the requirement resolves to `python-magic-bin` there. If you already have a broken `python-magic`, `pip uninstall python-magic` first.
- If `yara-python` cannot load `libyara.dll`, the scanner still runs; option **d** shows the error. To repair it:

  ```powershell
  pip uninstall yara-python
  pip install --only-binary :all: yara-python
  ```

  Installing the Microsoft Visual C++ 2015–2022 redistributable fixes it in most cases.

## Performance and limits

- Files larger than 500 MB are skipped with a note rather than half-scanned.
- Content engines read at most 64 MB from the front of a file; bigger files still get hashes, entropy and header analysis, and the result says so.
- Directory scans skip `.git`, `node_modules`, `__pycache__`, virtualenv folders and the scanner's own `quarantine/` and `reports/` so it never scans its own output.
- VirusTotal uploads are skipped automatically above the 32 MB API limit; hash lookups still run.
- Hashing and entropy read the file once each and stream in chunks, so memory use stays flat regardless of file size.

## Troubleshooting

**Something crashed.** The scanner prints a short summary and writes the full traceback to `scanner_crash.log` (next to the exe, or in `%LOCALAPPDATA%\Xpl01tsFileScanner`). Open menu option **d** to see which engine is unavailable and why.

**An engine shows as unavailable.** Option **d** lists the exact exception. Usually it is a missing package (option 9 installs it), a broken binary wheel (see the YARA and Windows notes), or no `clamscan` on `PATH`.

**A file was flagged that you trust.** Check which engine raised it: the console output and reports group findings by engine and severity. Behaviour and signature findings are heuristics and can produce false positives on legitimate security tooling, admin scripts and exploit research. A known-malware hash hit or a ClamAV infection is a much stronger signal.

**The screen clears too aggressively.** Menu option **s** toggles it, or just launch in a terminal that is not a TTY and clearing is disabled automatically. Reports and logs are never affected.

## Disclaimer

This tool is intended for personal and educational use, on files you own or have explicit permission to analyze. It is a heuristic-based aid, not a replacement for a dedicated, regularly-updated antivirus product. False positives and false negatives are both possible, and a CLEAN verdict is not a guarantee of safety.
