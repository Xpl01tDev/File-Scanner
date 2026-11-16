import hashlib
import math
import os
import re
import json
import copy
import shutil
import struct
import sys
import time
import traceback
import logging
import datetime
import subprocess
import socket
import platform
import csv
import html
import io
import importlib.util
import urllib.request
import urllib.error
from pathlib import Path
from collections import Counter
from typing import Optional

try:
    import threading
    _DB_LOCK = threading.RLock()
except Exception:
    class _DummyLock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    _DB_LOCK = _DummyLock()

BANNER = r"""
██╗  ██╗██████╗ ██╗      ██████╗  ██╗████████╗███████╗    ███████╗██╗██╗     ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
╚██╗██╔╝██╔══██╗██║     ██╔═████╗███║╚══██╔══╝██╔════╝    ██╔════╝██║██║     ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ╚███╔╝ ██████╔╝██║     ██║██╔██║╚██║   ██║   ███████╗    █████╗  ██║██║     █████╗      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔██╗ ██╔═══╝ ██║     ████╔╝██║ ██║   ██║   ╚════██║    ██╔══╝  ██║██║     ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██╔╝ ██╗██║     ███████╗╚██████╔╝ ██║   ██║   ███████║    ██║     ██║███████╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""

SCANNER_NAME = "Xpl01ts File Scanner"

ENGINE_NOTES = []


def _import_engine(module_name, friendly, flag_name, importer=None):
    try:
        if importer is not None:
            return importer()
        return importlib.import_module(module_name)
    except BaseException as e:
        ENGINE_NOTES.append(f"{friendly} disabled: {type(e).__name__}: {e}")
        return None


requests = _import_engine("requests", "VirusTotal", "HAS_REQUESTS")
HAS_REQUESTS = requests is not None

Observer = None
FileSystemEventHandler = None
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except BaseException as e:
    HAS_WATCHDOG = False
    ENGINE_NOTES.append(f"watchdog disabled: {type(e).__name__}: {e}")

magic = _import_engine("magic", "libmagic MIME detection", "HAS_MAGIC")
HAS_MAGIC = magic is not None

pyclamd = _import_engine("pyclamd", "ClamAV daemon", "HAS_PYCLAMD")
HAS_PYCLAMD = pyclamd is not None

yara = _import_engine("yara", "YARA", "HAS_YARA")
HAS_YARA = yara is not None

for _name, _flag, _mod in (("requests", "HAS_REQUESTS", "requests"),
                           ("magic", "HAS_MAGIC", "magic"),
                           ("pyclamd", "HAS_PYCLAMD", "pyclamd"),
                           ("yara", "HAS_YARA", "yara")):
    if globals().get(_flag) and globals().get(_name) is None:
        globals()[_flag] = False
        ENGINE_NOTES.append(f"{_name} reported as missing after import")


FROZEN = bool(getattr(sys, "frozen", False))


def _program_folder() -> str:
    if FROZEN:
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _per_user_folder() -> str:
    if os.name == "nt":
        root = (os.environ.get("LOCALAPPDATA")
                or os.path.join(os.path.expanduser("~"), "AppData", "Local"))
        target = os.path.join(root, "Xpl01tsFileScanner")
    else:
        target = os.path.join(os.path.expanduser("~"), ".local", "share", "xpl01ts-file-scanner")
    os.makedirs(target, exist_ok=True)
    return target


def _pick_data_folder() -> str:
    candidates = [_program_folder()]
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        candidates.append(bundle)
    for here in candidates:
        probe = os.path.join(here, ".write_test")
        try:
            with open(probe, "w") as fh:
                fh.write("x")
            os.remove(probe)
            return here
        except Exception:
            continue
    return _per_user_folder()


BASE_DIR = _pick_data_folder()
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
LOG_FILE = os.path.join(BASE_DIR, "scanner.log")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
HASH_DB_FILE = os.path.join(BASE_DIR, "malware_hashes.json")
QUARANTINE_MANIFEST = os.path.join(QUARANTINE_DIR, "manifest.json")
SCAN_HISTORY_FILE = os.path.join(BASE_DIR, "scan_history.json")
DEFAULT_EXPORT_DIR = Path.home() / "Documents" / "Xpl01ts File Scanner Reports"
VT_API_KEY = os.environ.get("VT_API_KEY", "")
REQUIREMENTS_URL = "https://raw.githubusercontent.com/Linuxxuserr/File-Scanner/refs/heads/main/requirements.txt"

PACKAGE_MAP = {
    "requests": "requests",
    "watchdog": "watchdog",
    "magic": "python-magic-bin" if os.name == "nt" else "python-magic",
    "pyclamd": "pyclamd",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".msi",
    ".pif", ".lnk", ".inf", ".reg", ".sct", ".shb", ".shs", ".gadget",
    ".jar", ".class", ".swf", ".apk", ".deb", ".rpm", ".cab", ".msu",
    ".py", ".pyw", ".rb", ".pl", ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".sh", ".bash", ".csh", ".ksh", ".so", ".dylib",
}

TEXT_EXTENSIONS = {
    ".py", ".pyw", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".sh", ".bash",
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".rb", ".pl",
    ".hta", ".reg", ".inf", ".sct", ".lnk", ".hta",
}

PLAIN_TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".conf", ".properties", ".env", ".md", ".rst", ".tex",
    ".html", ".htm", ".css", ".scss", ".sql", ".bat2", ".service", ".plist",
}

_handlers = []
try:
    _handlers.append(logging.FileHandler(LOG_FILE, mode="a", encoding="utf-8"))
except Exception:
    pass
_console = logging.StreamHandler(sys.stdout)
_console.setLevel(logging.CRITICAL)
_handlers.append(_console)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=_handlers,
)
log = logging.getLogger("Scanner")
CONSOLE_HANDLER = _console


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    BLINK = "\033[5m"
    RESET = "\033[0m"


def _terminal_takes_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not getattr(stream, "isatty", lambda: False)():
        return False
    if os.name == "nt":
        if os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"):
            return True
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            return bool(kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7))
        except Exception:
            return False
    return True


def set_colours(enabled: bool):
    if enabled:
        return
    for name in dir(C):
        if not name.startswith("_"):
            setattr(C, name, "")


COLOUR_ENABLED = _terminal_takes_colour()
set_colours(COLOUR_ENABLED)

UI_STATE = {
    "clear": True,
    "plain": False,
    "interactive": False
}


def wipe_screen():
    if UI_STATE["plain"] or not UI_STATE["clear"]:
        return
    try:
        if os.name == "nt":
            os.system("cls")
        else:
            sys.stdout.write("\033[2J\033[3J\033[H")
            sys.stdout.flush()
    except Exception:
        pass


def draw_banner():
    wipe_screen()
    sys.stdout.write(BANNER)
    total_hashes = 0
    try:
        if os.path.exists(HASH_DB_FILE):
            with open(HASH_DB_FILE) as fh:
                data = json.load(fh)
            total_hashes = sum(len(data.get(a, [])) for a in ("md5", "sha1", "sha256"))
    except Exception:
        pass
    engines = ["heuristics", "file-forensics"]
    if _clamav_signature_files():
        engines.append("clamav-patterns")
    if shutil.which("clamscan") or HAS_PYCLAMD:
        engines.append("clamav")
    if HAS_YARA:
        engines.append("yara")
    if VT_API_KEY:
        engines.append("virustotal")
    print(f"{C.DIM}  hash-DB: {total_hashes} hashes  |  engines: {', '.join(engines)}{C.RESET}")
    print(f"{C.DIM}  {platform.system()} {platform.release()}  |  python "
          f"{platform.python_version()}  |  {BASE_DIR}{C.RESET}")
    print(f"{C.DIM}{'─' * 76}{C.RESET}")


def missing_pip_packages() -> list:
    missing = []
    for import_name, pip_name in PACKAGE_MAP.items():
        if importlib.util.find_spec(import_name) is None:
            missing.append(pip_name)
    return missing


def download_requirements_list(url: str) -> Optional[list]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "file-scanner-installer"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8")
        lines = [
            line.strip() for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return lines
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.error(f"Failed to fetch requirements.txt: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error fetching requirements.txt: {e}")
        return None


def _package_name_from_line(requirement_line: str) -> str:
    return re.split(r"[=<>!~\[;]", requirement_line)[0].strip()


def _bundled_engines():
    rows = []
    for import_name, pip_name in PACKAGE_MAP.items():
        rows.append((pip_name, importlib.util.find_spec(import_name) is not None))
    rows.append(("yara-python", importlib.util.find_spec("yara") is not None))
    return rows


def run_package_install():
    if FROZEN:
        print(f"{C.BOLD}Standalone build{C.RESET}  {os.path.abspath(sys.executable)}")
        _divider()
        for pip_name, ok in _bundled_engines():
            mark = f"{C.GREEN}bundled{C.RESET}" if ok else f"{C.YELLOW}not bundled{C.RESET}"
            print(f"  {pip_name:<18} {mark}")
        _divider()
        print("  Extra engines are compiled into the exe at build time, so they")
        print("  cannot be pip-installed into it. For the full set use the")
        print("  source install:  pip install -r requirements.txt  then  python scanner.py")
        return False

    missing = missing_pip_packages()

    if not missing:
        print(f"{C.GREEN}{C.BOLD}All required packages are already installed.{C.RESET}")
        return True

    print(f"{C.YELLOW}{C.BOLD}The following packages are not installed:{C.RESET}")
    for pkg in missing:
        print(f"  {C.YELLOW}- {pkg}{C.RESET}")

    answer = input(f"\n{C.BOLD}Install missing packages now? (y/n): {C.RESET}").strip().lower()

    if answer not in ("y", "yes"):
        print(f"{C.YELLOW}Nothing installed. The scanner still runs, "
              f"those engines stay off.{C.RESET}")
        return False

    print(f"{C.GREEN}{C.BOLD}Installing packages right now!{C.RESET}")

    requirements = download_requirements_list(REQUIREMENTS_URL)
    if requirements is None:
        print(f"{C.RED}Could not fetch the requirements list from:{C.RESET} {REQUIREMENTS_URL}")
        print(f"{C.YELLOW}Install them by hand: pip install {' '.join(missing)}{C.RESET}")
        return False

    missing_lower = {m.lower() for m in missing}
    to_install = [
        line for line in requirements
        if _package_name_from_line(line).lower() in missing_lower
    ]

    if not to_install:
        to_install = missing

    for requirement in to_install:
        print(f"{C.CYAN}Installing package: {requirement}{C.RESET}")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", requirement],
                stdout=subprocess.DEVNULL if False else None,
            )
        except subprocess.CalledProcessError as e:
            print(f"{C.RED}{C.BOLD}Failed to install {requirement}: {e}{C.RESET}")
            print(f"{C.YELLOW}Stopping here; install it manually and try again.{C.RESET}")
            return False

    still_missing = missing_pip_packages()
    if still_missing:
        print(f"{C.YELLOW}Installed, but still missing (may need a manual install): "
              f"{', '.join(still_missing)}{C.RESET}")
    else:
        print(f"{C.GREEN}{C.BOLD}All packages installed successfully!{C.RESET}")


def warn_about_missing_packages():
    missing = missing_pip_packages()
    if missing:
        print(f"{C.YELLOW}Note: optional packages not installed: {', '.join(missing)}{C.RESET}")
        print(f"{C.YELLOW}Run '{os.path.basename(sys.argv[0])} install' to add them.{C.RESET}\n")


def load_hash_db() -> dict:
    db = {"md5": set(), "sha1": set(), "sha256": set()}
    if os.path.exists(HASH_DB_FILE):
        try:
            with open(HASH_DB_FILE) as f:
                data = json.load(f)
            for algo in db:
                for h in data.get(algo, []):
                    db[algo].add(h.lower())
            log.info(f"Malware DB loaded: {sum(len(v) for v in db.values())} hashes")
        except Exception as e:
            log.warning(f"Failed to load malware DB: {e}")
    return db


def save_hash_db(db: dict):
    payload = {k: sorted(v) for k, v in db.items()}
    tmp = HASH_DB_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, HASH_DB_FILE)
    except Exception as e:
        log.error(f"Failed to save malware DB: {e}")
        raise


def remember_hash(hash_db: dict, algo: str, hash_val: str):
    with _DB_LOCK:
        hash_db.setdefault(algo, set()).add(hash_val.lower().strip())
        save_hash_db(hash_db)


def hash_file(filepath: str) -> dict:
    digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(),
               "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with open(filepath, "rb") as handle:
        while block := handle.read(65536):
            for digest in digests.values():
                digest.update(block)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


MAX_ENTROPY_READ = 256 * 1024 * 1024


def entropy_breakdown(filepath: str) -> dict:
    window_scores = []
    high_windows = blazing_windows = quiet_windows = flat_windows = 0

    with open(filepath, "rb") as handle:
        while True:
            block = handle.read(4096)
            if not block:
                break
            window = byte_entropy(block)
            window_scores.append(window)
            if window > 7.5:
                blazing_windows += 1
            if window > 7.0:
                high_windows += 1
            if window < 1.0:
                quiet_windows += 1
            if window < 0.2 and len(block) == 4096:
                flat_windows += 1

    if not window_scores:
        return {"overall": 0.0, "max": 0.0, "avg": 0.0, "high_chunks": 0, "total_chunks": 0}

    return {
        "overall": _entropy_of_whole_file(filepath),
        "max": max(window_scores),
        "min": min(window_scores),
        "avg": sum(window_scores) / len(window_scores),
        "high_chunks": high_windows,
        "very_high_chunks": blazing_windows,
        "low_chunks": quiet_windows,
        "padded_chunks": flat_windows,
        "total_chunks": len(window_scores),
        "high_ratio": high_windows / len(window_scores) if window_scores else 0,
        "low_ratio": quiet_windows / len(window_scores) if window_scores else 0,
    }


def _entropy_of_whole_file(filepath: str) -> float:
    freq = Counter()
    n = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            freq.update(chunk)
            n += len(chunk)
            if n >= MAX_ENTROPY_READ:
                break
    if not n:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


MAGIC_BYTES = {
    b"MZ": "PE executable",
    b"\x7fELF": "ELF executable",
    b"PK": "ZIP / OOXML",
    b"\xca\xfe\xba\xbe": "Mach-O / Java Class",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"\x1f\x8b": "GZIP archive",
    b"Rar!": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "OLE / Office legacy",
    b"\xff\xd8\xff": "JPEG image",
    b"\x89PNG": "PNG image",
    b"GIF8": "GIF image",
    b"RIFF": "RIFF container",
    b"BM": "BMP image",
    b"\x1a\x45\xdf\xa3": "Matroska / WebM",
    b"OggS": "OGG media",
    b"ID3": "MP3 audio",
    b"SQLite format 3": "SQLite database",
    b"\x4d\x5a\x90\x00": "PE executable (DOS stub)",
    b"#!": "Script with shebang",
    b"\x25\x21\x50\x53": "PostScript",
    b"\x00asm": "WebAssembly module",
}


def identify_file_type(data: bytes) -> str:
    for magic_bytes, desc in MAGIC_BYTES.items():
        if data[:len(magic_bytes)] == magic_bytes:
            return desc
    return "Unknown"


def guess_mime_type(filepath: str) -> str:
    if HAS_MAGIC:
        try:
            return magic.Magic(mime=True).from_file(filepath)
        except Exception:
            pass
    ext_map = {
        ".exe": "application/x-dosexec", ".dll": "application/x-dosexec",
        ".pdf": "application/pdf", ".zip": "application/zip",
        ".py": "text/x-python", ".js": "application/javascript",
        ".sh": "application/x-shellscript", ".so": "application/x-sharedlib",
        ".jar": "application/java-archive", ".apk": "application/vnd.android.package-archive",
        ".docm": "application/vnd.ms-word.document.macroEnabled.12",
        ".xlsm": "application/vnd.ms-excel.sheet.macroEnabled.12",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".rtf": "application/rtf", ".hta": "application/hta",
        ".ps1": "text/x-powershell", ".lnk": "application/x-ms-shortcut",
        ".txt": "text/plain", ".log": "text/plain", ".csv": "text/csv",
        ".json": "application/json", ".xml": "application/xml",
        ".yml": "text/yaml", ".yaml": "text/yaml", ".md": "text/markdown",
        ".html": "text/html", ".htm": "text/html", ".css": "text/css",
        ".ini": "text/plain", ".cfg": "text/plain", ".env": "text/plain",
        ".toml": "text/plain", ".sql": "application/sql",
    }
    _, ext = os.path.splitext(filepath)
    return ext_map.get(ext.lower(), "application/octet-stream")


class PEAnalyzer:
    SENSITIVE_DLLS = {
        b"ws2_32.dll", b"wininet.dll", b"winhttp.dll", b"urlmon.dll",
        b"advapi32.dll", b"crypt32.dll", b"bcrypt.dll", b"ntdll.dll",
        b"kernel32.dll", b"psapi.dll", b"user32.dll", b"shell32.dll",
    }
    SENSITIVE_FUNCS = {
        b"VirtualAlloc", b"VirtualProtect", b"VirtualAllocEx", b"WriteProcessMemory",
        b"CreateRemoteThread", b"CreateRemoteThreadEx", b"LoadLibraryA", b"LoadLibraryW",
        b"GetProcAddress", b"WinExec", b"ShellExecuteA", b"ShellExecuteW",
        b"URLDownloadToFileA", b"URLDownloadToFileW", b"InternetOpenA", b"InternetReadFile",
        b"WSAStartup", b"connect", b"send", b"recv", b"CreateServiceA", b"RegSetValueExA",
        b"RegCreateKeyExA", b"SetWindowsHookExA", b"IsDebuggerPresent",
        b"CryptEncrypt", b"CryptGenKey", b"GetAsyncKeyState", b"OpenProcess",
        b"WriteFile", b"DeleteFileA", b"MoveFileA", b"CreateProcessA", b"CreateProcessW",
    }

    @staticmethod
    def is_pe(filepath: str) -> bool:
        try:
            with open(filepath, "rb") as f:
                if f.read(2) != b"MZ":
                    return False
                f.seek(0x3C)
                f.seek(struct.unpack("<I", f.read(4))[0])
                return f.read(4) == b"PE\x00\x00"
        except Exception:
            return False

    @staticmethod
    def parse_pe(filepath: str) -> dict:
        info = {"is_64bit": False, "sections": [], "suspicious_imports": [],
                "imports": [], "imphash_source": 0, "timestamp": None}
        try:
            with open(filepath, "rb") as f:
                f.seek(0x3C)
                pe_off = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_off + 4)
                info["is_64bit"] = struct.unpack("<H", f.read(2))[0] == 0x8664
                f.seek(pe_off + 8)
                ts = struct.unpack("<I", f.read(4))[0]
                if ts:
                    try:
                        info["timestamp"] = datetime.datetime.fromtimestamp(
                            ts, datetime.timezone.utc).isoformat()
                    except Exception:
                        info["timestamp"] = str(ts)
                f.seek(pe_off + 24)
                opt_size = struct.unpack("<H", f.read(2))[0]
                num_sec = struct.unpack("<H", f.read(2))[0]
                f.seek(pe_off + 24 + opt_size)
                for _ in range(min(num_sec, 30)):
                    sec = f.read(40)
                    if len(sec) < 40:
                        break
                    chars = struct.unpack("<I", sec[36:40])[0]
                    info["sections"].append({
                        "name": sec[:8].rstrip(b"\x00").decode("ascii", errors="replace"),
                        "virtual_size": struct.unpack("<I", sec[8:12])[0],
                        "raw_size": struct.unpack("<I", sec[16:20])[0],
                        "executable": bool(chars & 0x20000000),
                        "writable": bool(chars & 0x80000000),
                    })

                try:
                    f.seek(pe_off + 24)
                    opt = f.read(opt_size)
                    dd_off = 112 if info["is_64bit"] else 96
                    if len(opt) >= dd_off + 8:
                        imp_rva, imp_size = struct.unpack("<II", opt[dd_off:dd_off + 8])
                        if imp_rva:
                            imports = PEAnalyzer._read_imports(f, pe_off, opt_size,
                                                               num_sec, imp_rva, info["is_64bit"])
                            info["imports"] = imports
                            for entry in imports:
                                dll = entry["dll"].lower().encode()
                                if dll in PEAnalyzer.SENSITIVE_DLLS:
                                    info["suspicious_imports"].append(entry["dll"])
                                for fn in entry["functions"]:
                                    if fn.encode() in PEAnalyzer.SENSITIVE_FUNCS:
                                        info["suspicious_imports"].append(f"{entry['dll']}!{fn}")
                except Exception:
                    pass
        except Exception as e:
            info["error"] = str(e)
        return info

    @staticmethod
    def _read_pe_imports(f, pe_off, opt_size, num_sec, imp_rva, is64) -> list:
        f.seek(pe_off + 24 + opt_size)
        sec_hdrs = []
        for _ in range(min(num_sec, 30)):
            raw = f.read(40)
            if len(raw) < 40:
                break
            vsize = struct.unpack("<I", raw[8:12])[0]
            vaddr = struct.unpack("<I", raw[12:16])[0]
            raw_size = struct.unpack("<I", raw[16:20])[0]
            raw_ptr = struct.unpack("<I", raw[20:24])[0]
            sec_hdrs.append((vaddr, max(vsize, raw_size), raw_ptr, raw_size))

        def _rva_to_offset(rva):
            for vaddr, size, raw_ptr, raw_size in sec_hdrs:
                if vaddr <= rva < vaddr + size:
                    delta = rva - vaddr
                    if delta < raw_size:
                        return raw_ptr + delta
            return None

        out = []
        off = _rva_to_offset(imp_rva)
        if off is None:
            return out
        for _ in range(64):
            f.seek(off)
            desc = f.read(20)
            if len(desc) < 20 or desc == b"\x00" * 20:
                break
            name_rva = struct.unpack("<I", desc[12:16])[0]
            thunk_rva = struct.unpack("<I", desc[16:20])[0]
            name_off = _rva_to_offset(name_rva)
            dll = "?"
            if name_off is not None:
                f.seek(name_off)
                raw = f.read(64).split(b"\x00")[0]
                dll = raw.decode("ascii", errors="replace")
            funcs = []
            t_off = _rva_to_offset(thunk_rva) if thunk_rva else None
            if t_off is not None:
                step = 8 if is64 else 4
                for _ in range(256):
                    f.seek(t_off)
                    entry = f.read(step)
                    if len(entry) < step or entry == b"\x00" * step:
                        break
                    val = struct.unpack("<Q" if is64 else "<I", entry)[0]
                    if val & (1 << (63 if is64 else 31)):
                        funcs.append(f"ord{val & 0xffff}")
                    else:
                        hn = _rva_to_offset(val & 0x7fffffff)
                        if hn is None:
                            break
                        f.seek(hn + 2)
                        fname = f.read(64).split(b"\x00")[0].decode("ascii", errors="replace")
                        if fname:
                            funcs.append(fname)
                    t_off += step
            out.append({"dll": dll, "functions": funcs[:64]})
            off += 20
        return out


DANGEROUS_IMPORTS_PY = [
    "os.system", "subprocess", "ctypes", "ctypes.windll", "ctypes.CDLL",
    "shutil.rmtree", "os.remove", "os.unlink", "os.rename",
    "crypto", "cipher", "AES", "Fernet", "encrypt", "decrypt",
    "base64.b64decode", "codecs.decode", "exec(", "eval(",
    "compile(", "__import__",
    "socket.socket", "socket.connect", "socket.bind", "socket.listen",
    "urllib.request", "requests.post", "requests.get",
    "paramiko", "ftplib", "smtplib",
    "winreg", "win32api", "win32com",
    "keyboard", "pynput", "pyautogui",
    "psutil", "threading.Thread", "multiprocessing",
    "webbrowser.open", "subprocess.Popen",
]

DANGEROUS_IMPORTS_JS = [
    "child_process", "fs.writeFileSync", "fs.unlinkSync",
    "require('child_process')", "require('fs')",
    "process.env", "process.exit",
    "execSync", "spawnSync", "exec(",
    "ActiveXObject", "WScript.Shell",
    "XMLHttpRequest", "fetch(",
    "navigator", "window.location",
]

DANGEROUS_IMPORTS_PS = [
    "Invoke-Expression", "IEX", "Invoke-WebRequest",
    "DownloadString", "DownloadFile",
    "Start-Process", "New-Object Net.WebClient",
    "[System.Reflection.Assembly]::Load",
    "Add-Type", "DllImport",
    "Set-MpPreference", "DisableRealtimeMonitoring",
    "Get-WmiObject", "Get-Process",
    "Invoke-Mimikatz", "Invoke-CredentialInjection",
    "EncodedCommand", "-enc ", "-e ",
    "Bypass", "-ExecutionPolicy Bypass",
]

DANGEROUS_IMPORTS_BAT = [
    "del /f /q", "rd /s /q", "format ",
    "cipher /w:", "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "reg add", "schtasks /create",
    "net user", "net localgroup administrators",
    "taskkill /f", "shutdown /s",
    "powershell -enc", "powershell -e ",
    "curl ", "wget ", "certutil -urlcache",
    "bitsadmin /transfer",
]

BEHAVIOUR_PATTERNS = [
    (r"(?i)(?:your|all|the|my)\s+(?:files?|data|documents?|photos?)\s+(?:have been|has been|are|is)\s+encrypt", "Ransomware encryption notice"),
    (r"(?i)decrypt(?:ion)?\s+(?:key|tool|software|service)", "Ransomware decryption demand"),
    (r"(?i)pay\s+(?:a\s+)?ransom|bitcoin\s+(?:wallet|address|payment)|monero|wire.transfer", "Ransom payment demand"),
    (r"(?i)(?:files?\s+will\s+be|data\s+will\s+be|everything\s+will\s+be)\s+(?:deleted|destroyed|lost|gone)", "Destruction threat"),
    (r"(?i)(?:time\s+remaining|countdown|hours?\s+remaining|days?\s+remaining)", "Ransom countdown timer"),
    (r"(?i)(?:enter\s+(?:the\s+)?(?:decryption|unlock|encryption)\s+key|correct\s+key)", "Ransom key input"),
    (r"(?i)(?:subprocess\.call|subprocess\.Popen|subprocess\.run|os\.system)\s*\(", "External process execution"),
    (r"(?i)(?:shutil\.rmtree|os\.remove|os\.unlink|os\.system\s*\(\s*['\"]rm)", "File system destruction"),
    (r"(?i)(?:keyboard\.block_key|keyboard\.unhook|block_key|unhook_all)", "Keyboard blocking/hooking"),
    (r"(?i)(?:encrypt\s*\(|\.encrypt\(|AES\.|Fernet|cipher\.|Crypto\.|pycryptodome)", "Encryption operations"),
    (r"(?i)(?:os\.walk|glob\.glob|os\.listdir|pathlib|Path\s*\()", "File enumeration"),
    (r"(?i)(?:fullscreen|topmost|overrideredirect|wm_delete_window)", "Full-screen UI lock"),
    (r"(?i)(?:discord\.com/api/webhooks|webhook|exfil|send.*(?:info|data|screenshot))", "Data exfiltration"),
    (r"(?i)(?:get_pc_info|gethostname|getuser|get_adapters_info|public.ip|local.ip)", "System fingerprinting"),
    (r"(?i)(?:socket\.SOCK_DGRAM|socket\.connect|socket\.bind|reverse.?shell)", "Network socket operations"),
    (r"(?i)(?:base64\.b64encode|requests\.post.*base64|b64encode)", "Base64 data encoding/exfil"),
    (r"(?i)(?:screenshot|capture|ImageGrab|pyautogui\.screenshot)", "Screenshot capture"),
    (r"(?i)(?:watchdog|restart|re-launch|reopen|persistence|survive|kill)", "Persistence/watchdog mechanism"),
    (r"(?i)(?:system32|\\\\windows\\\\|C:\\\\Users|\\\\Documents\\\\|\\\\Desktop\\\\)", "Windows system path access"),
    (r"(?i)(?:DisableRealtimeMonitoring|Set-MpPreference|Add-MpPreference|exclusion)", "AV evasion/disabling"),
    (r"(?i)(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit)", "Shadow copy/catalog deletion"),
    (r"(?i)(?:shutdown|logoff|restart.*\/[rf]|\/s\s+\/f\s+\/t)", "System shutdown/restart"),
    (r"(?i)(?:net\s+user.*\/add|net\s+localgroup.*admin|schtasks|at\s+\d)", "User/scheduled task creation"),
    (r"(?i)(?:curl\s+.*-o|wget\s+.*-O|Invoke-WebRequest.*-OutFile|DownloadFile)", "Remote file download"),
    (r"(?i)(?:certutil\s+-urlcache|bitsadmin\s+/transfer|start-bitstransfer)", "LOLBin download"),
    (r"(?i)(?:\\\\[a-z0-9]+\\[a-z0-9\$]+|\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", "Network share/IP access"),
    (r"(?i)(?:GetAsyncKeyState|SetWindowsHookEx|GetKeyState|keylog|GetKeyboardState)", "Keylogging"),
    (r"(?i)(?:mimikatz|sekurlsa|lsadump|bloodhound|cobalt.strike|metasploit|msfvenom)", "Offensive security tooling"),
    (r"(?i)(?:VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection)", "Process injection"),
    (r"(?i)(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer|AmsiOpenSession|ETW.*patch)", "AMSI/ETW bypass"),
    (r"(?i)(?:IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|anti.?debug)", "Anti-debugging"),
    (r"(?i)(?:VMware|VBox|VirtualBox|QEMU|SbieDll|Sandboxie|Cuckoo|wine_get_unix_file_name)", "Anti-VM/sandbox"),
    (r"(?i)(?:tor2web|\.onion|tor.*proxy|socks5|SOCKS)", "Tor/anonymization"),
    (r"(?i)(?:ransom|hostage)", "Ransomware language"),
    (r"(?i)(?:your\s+(?:files?|data|documents?|photos?|everything)\s+(?:has|have|are)\s+encrypt)", "Ransomware language"),
    (r"(?i)(?:pay.*bitcoin|bitcoin.*address.*send)", "Ransomware language"),
    (r"(?i)(?:FSociety|WannaCry|Petya|NotPetya|Locky|Cerber|Dharma|Phobos)", "Known ransomware family references"),
]

MAGIC_BYTES_SUSPICIOUS = {
    b"MZ": 8,
    b"\x7fELF": 8,
    b"PK": 3,
    b"\xca\xfe\xba\xbe": 7,
    b"\xfe\xed\xfa\xce": 7,
    b"\xfe\xed\xfa\xcf": 7,
    b"\xd0\xcf\x11\xe0": 6,
}


class ScanResult:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.file_size = 0
        self.hashes = {}
        self.magic = ""
        self.mime = ""
        self.entropy = {}
        self.pe_info = {}
        self.text_findings = []
        self.signature_matches = []
        self.hash_db_match = False
        self.clamav_result = None
        self.clamav_pattern_result = None
        self.yara_result = None
        self.forensics = {}
        self.vt_hash_result = None
        self.vt_upload_result = None
        self.risk_score = 0
        self.risk_level = "CLEAN"
        self.scan_time = 0
        self.errors = []
        self.is_text_file = False
        self.scan_engines = []
        self.notes = []

    def is_flagged(self) -> bool:
        return self.risk_level not in ("CLEAN", "LOW")

    def severity_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.text_findings:
            counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1
        for s in self.signature_matches:
            sev = s.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        for rule in (self.forensics.get("findings") or []):
            sev = rule.get("severity", "LOW")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def has_hashes(self) -> bool:
        return bool(self.hashes.get("sha256"))

    def to_dict(self) -> dict:
        return {
            "file": self.filepath,
            "filename": self.filename,
            "size_bytes": self.file_size,
            "hashes": self.hashes,
            "magic": self.magic,
            "mime": self.mime,
            "entropy": self.entropy,
            "pe_info": self.pe_info,
            "is_text_file": self.is_text_file,
            "text_findings_count": len(self.text_findings),
            "text_findings": self.text_findings[:100],
            "signature_matches": self.signature_matches,
            "hash_db_match": self.hash_db_match,
            "clamav": self.clamav_result,
            "clamav_patterns": self.clamav_pattern_result,
            "yara": self.yara_result,
            "forensics": self.forensics,
            "virustotal_hash": self.vt_hash_result,
            "virustotal_upload": self.vt_upload_result,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "flagged": self.is_flagged(),
            "severity_counts": self.severity_counts(),
            "scan_engines": self.scan_engines,
            "notes": self.notes,
            "scan_time_seconds": round(self.scan_time, 3),
            "errors": self.errors,
        }


def work_out_risk(result: ScanResult) -> tuple:
    points = 0

    if result.hash_db_match:
        return 100, "CRITICAL"

    clam_verdict = result.clamav_result
    if clam_verdict:
        if clam_verdict.get("infected"):
            points += 60
        elif clam_verdict.get("error"):
            pass

    clam_db_hit = result.clamav_pattern_result
    if clam_db_hit and clam_db_hit.get("matched"):
        sev = clam_db_hit.get("severity", "HIGH")
        points += {"CRITICAL": 85, "HIGH": 55, "MEDIUM": 30}.get(sev, 30)

    yara_hits = result.yara_result
    if yara_hits and yara_hits.get("matches"):
        for m in yara_hits["matches"]:
            sev = m.get("severity", "MEDIUM")
            points += {"CRITICAL": 80, "HIGH": 50, "MEDIUM": 25, "LOW": 10}.get(sev, 20)

    container_hits = result.forensics.get("findings") if result.forensics else None
    if container_hits:
        for f in container_hits:
            sev = f.get("severity", "MEDIUM")
            points += {"CRITICAL": 45, "HIGH": 25, "MEDIUM": 10, "LOW": 3}.get(sev, 5)
        if result.forensics.get("bomb"):
            points += 20
        if result.forensics.get("embedded_executable"):
            points += 20

    virus_total = result.vt_hash_result
    if virus_total and "malicious" in virus_total:
        detections = virus_total["malicious"]
        engine_count = virus_total.get("total_engines", 70)
        if detections > 0:
            ratio = detections / max(engine_count, 1)
            if detections >= 20 or ratio > 0.4:
                points += 60
            elif detections >= 10 or ratio > 0.2:
                points += 45
            elif detections >= 5:
                points += 35
            elif detections >= 2:
                points += 25
            elif detections >= 1:
                points += 15
        suspicious = virus_total.get("suspicious", 0)
        if suspicious > 5:
            points += 15
        elif suspicious > 0:
            points += 8

    vt_upload = result.vt_upload_result
    if vt_upload and "malicious" in vt_upload:
        detections = vt_upload["malicious"]
        engine_count = vt_upload.get("total_engines", 70)
        if detections > 0:
            ratio = detections / max(engine_count, 1)
            if detections >= 20 or ratio > 0.4:
                points += 60
            elif detections >= 10 or ratio > 0.2:
                points += 45
            elif detections >= 5:
                points += 35
            elif detections >= 2:
                points += 25
            elif detections >= 1:
                points += 15
        suspicious = vt_upload.get("suspicious", 0)
        if suspicious > 5:
            points += 15
        elif suspicious > 0:
            points += 8

    entropy = result.entropy.get("overall", 0)
    if entropy > 7.8:
        points += 18
    elif entropy > 7.3:
        points += 12
    elif entropy > 6.8:
        points += 6

    high_ratio = result.entropy.get("high_ratio", 0)
    if high_ratio > 0.5:
        points += 12
    elif high_ratio > 0.3:
        points += 6

    very_high = result.entropy.get("very_high_chunks", 0)
    if very_high > 50:
        points += 8
    elif very_high > 10:
        points += 4

    padded_windows = result.entropy.get("padded_chunks", 0)
    if padded_windows > 100:
        points += 6
    elif padded_windows > 20:
        points += 3

    if result.pe_info:
        sections = result.pe_info.get("sections", [])
        exec_writable = sum(1 for s in sections if s.get("executable") and s.get("writable"))
        if exec_writable >= 3:
            points += 15
        elif exec_writable >= 1:
            points += 8

        for s in sections:
            if s.get("raw_size", 0) > 0:
                ratio = s.get("virtual_size", 0) / s["raw_size"]
                if ratio > 10:
                    points += 10
                    break

        packed_names = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".mpress1",
                        ".themida", ".vmp0", ".vmp1", ".petite", ".nsp0", "pec1", "pec2"}
        for s in sections:
            if s.get("name", "").lower() in packed_names:
                points += 8
                break
        sensitive = result.pe_info.get("suspicious_imports", [])
        if len(sensitive) >= 12:
            points += 15
        elif len(sensitive) >= 6:
            points += 8
        elif sensitive:
            points += 3

        ts = result.pe_info.get("timestamp")
        if ts:
            try:
                when = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if when > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2):
                    points += 6
            except Exception:
                pass

    if result.magic in MAGIC_BYTES_SUSPICIOUS:
        points += MAGIC_BYTES_SUSPICIOUS[result.magic]

    dangerous_mimes = {"application/x-dosexec", "application/x-msdownload",
                       "application/x-executable", "application/x-sharedlib",
                       "application/java-archive", "application/x-python-bytecode"}
    if result.mime in dangerous_mimes:
        points += 8

    text_hits = result.text_findings
    if text_hits:
        critical_hits = sum(1 for f in text_hits if f.get("severity") == "CRITICAL")
        high_hits = sum(1 for f in text_hits if f.get("severity") == "HIGH")
        medium_hits = sum(1 for f in text_hits if f.get("severity") == "MEDIUM")
        low_hits = sum(1 for f in text_hits if f.get("severity") == "LOW")
        engine_count = len(text_hits)

        points += critical_hits * 22
        points += high_hits * 12
        points += medium_hits * 6
        points += low_hits * 2

        if engine_count >= 15:
            points += 50
        elif engine_count >= 10:
            points += 40
        elif engine_count >= 7:
            points += 30
        elif engine_count >= 5:
            points += 20
        elif engine_count >= 3:
            points += 12
        elif engine_count >= 1:
            points += 5

        categories = set(f.get("category", "") for f in text_hits)
        category_count = len(categories)
        if category_count >= 6:
            points += 30
        elif category_count >= 5:
            points += 25
        elif category_count >= 4:
            points += 20
        elif category_count >= 3:
            points += 15
        elif category_count >= 2:
            points += 8

        combos = [
            ({"ransomware", "persistence", "exfiltration"}, 25),
            ({"ransomware", "encryption", "file_access"}, 20),
            ({"persistence", "evasion", "process_execution"}, 15),
            ({"exfiltration", "reconnaissance"}, 10),
            ({"ransomware", "destruction"}, 20),
            ({"encryption", "file_access", "exfiltration"}, 15),
        ]
        for combo, extra in combos:
            if combo.issubset(categories):
                points += extra

    critical_rules = 0
    high_rules = 0
    for sig in result.signature_matches:
        sev = sig.get("severity", "LOW")
        if sev == "CRITICAL":
            points += 18
            critical_rules += 1
        elif sev == "HIGH":
            points += 10
            high_rules += 1
        elif sev == "MEDIUM":
            points += 5
        elif sev == "LOW":
            points += 2

    rule_hits = len(result.signature_matches)
    if rule_hits >= 5:
        points += 25
    elif rule_hits >= 3:
        points += 15
    elif rule_hits >= 1:
        points += 5

    if critical_rules >= 3:
        points += 20
    elif critical_rules >= 2:
        points += 12
    if high_rules >= 3:
        points += 10

    hard_indicators = [
        critical_rules > 0,
        bool(clam_verdict and clam_verdict.get("infected")),
        bool(clam_db_hit and clam_db_hit.get("matched") and clam_db_hit.get("severity") == "CRITICAL"),
        bool(yara_hits and any(str(m.get("severity", "")).upper() == "CRITICAL"
                         for m in (yara_hits.get("matches") or []))),
    ]
    if any(hard_indicators):
        points = max(points, 70)

    points = min(points, 100)

    if points >= 70:
        verdict = "CRITICAL"
    elif points >= 45:
        verdict = "HIGH"
    elif points >= 20:
        verdict = "MEDIUM"
    elif points >= 5:
        verdict = "LOW"
    else:
        verdict = "CLEAN"

    return points, verdict


def _line_is_comment_or_rule(line: str) -> bool:
    stripped = line.strip()

    if stripped.startswith("#"):
        return True
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return True
    if stripped.upper().startswith("REM ") or stripped.upper().startswith("::"):
        return True
    if re.match(r'''^\s*\(\s*r["']''', stripped):
        return True
    if re.match(r'''^\s*["']\s*r["']''', stripped):
        return True
    if re.match(r'''^\s*(?:rule|signature|pattern|match)\s+\w+''', stripped, re.IGNORECASE):
        return True
    if re.match(r'''^\s*["']?(?:name|rule|severity|pattern|description|category)\s*["']?\s*[:=]''', stripped, re.IGNORECASE):
        return True
    if re.match(r'''\s*\{\s*["'](?:name|rule)["']\s*:''', stripped):
        return True
    if re.match(r'''^\s*["'][A-Z][a-z].*(?:ransomware|ransom|encrypt|exfil|hook|bypass|evasion|watchdog|persistence|enumeration|fingerprint|destruction|injection|keylog|download|shutdown|creation|capture|socket|encoding|lock|timer|demand|threat|bypass|monitor|attack|access|tool|language|references|mechanism|operations|cancellation|operations|interception|detection|disabling|evasion|tooling|deletion|deletion|download|access|logging|dumping|locking|hijack|targeting|bypass)\b''', stripped):
        return True

    return False


def _looks_like_a_scanner(filepath: str) -> bool:
    try:
        with open(filepath, "r", errors="replace") as f:
            head = f.read(32768)
    except Exception:
        return False

    scanner_indicators = [
        r"(?:class\s+\w*Scanner|def\s+scan_file|def\s+calculate_risk)",
        r"(?:MALICIOUS_BEHAVIOR_PATTERNS|SIGNATURE_RULES|YARA_LIKE_RULES)",
        r"(?:def\s+signature_scan|def\s+text_based_analysis|def\s+compute_entropy)",
        r"(?:risk_score|risk_level|ScanResult|threat_detect|quarantine)",
        r"(?:class\s+\w*(?:Engine|Detector|Analyzer|Heuristic|Result))",
        r"(?:BASE_DIR|QUARANTINE_DIR|REPORT_DIR|KNOWN_MALWARE_DB|VT_API_KEY)",
        r"(?:clamav|ClamAV|clamscan|pyclamd|virustotal)",
        r"(?:def\s+quarantine_file|def\s+print_result|def\s+save_report)",
        r"(?:def\s+load_malware_db|def\s+save_malware_db)",
        r"(?:hashtools|hashlib|compute_hashes|HashComputer)",
    ]

    hits = 0
    for pat in scanner_indicators:
        if re.search(pat, head):
            hits += 1

    return hits >= 4


def look_at_behaviour(filepath: str, raw_content: bytes = None) -> list:
    findings = []
    try:
        if raw_content is None:
            raw_content = open(filepath, "rb").read()

        if len(raw_content) == 0:
            return findings

        if _is_binary_data(raw_content):
            return findings

        content = None
        for enc in ("utf-8", "utf-8-sig", "latin-1", "ascii", "utf-16-le", "cp1252"):
            try:
                content = raw_content.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if content is None:
            return findings

        if _looks_like_a_scanner(filepath):
            return findings

        lines = content.split("\n")

        for pattern_str, description in BEHAVIOUR_PATTERNS:
            try:
                matches_in_file = list(re.finditer(pattern_str, content, re.IGNORECASE | re.DOTALL))
            except re.error:
                continue

            if not matches_in_file:
                continue

            for m in matches_in_file[:3]:
                line_num = content[:m.start()].count("\n") + 1
                match_line = lines[line_num - 1] if line_num <= len(lines) else ""

                if _line_is_comment_or_rule(match_line):
                    continue

                start = max(0, m.start() - 40)
                end = min(len(content), m.end() + 40)
                context = content[start:end].replace("\n", " ").strip()

                if re.search(r'''r["'][\^$(]|\\x[0-9a-f]{2}\\x|\(\?i\)|\["'\]severity''', context):
                    continue

                severity = "MEDIUM"
                cat = "generic"

                desc_lower = description.lower()
                if "ransomware" in desc_lower or "ransom" in desc_lower:
                    severity = "CRITICAL"
                    cat = "ransomware"
                elif "destruction" in desc_lower or "delete" in desc_lower or "destroy" in desc_lower:
                    severity = "CRITICAL"
                    cat = "destruction"
                elif "injection" in desc_lower or "anti-debug" in desc_lower or "bypass" in desc_lower:
                    severity = "HIGH"
                    cat = "evasion"
                elif "exfiltration" in desc_lower or "webhook" in desc_lower or "screenshot" in desc_lower:
                    severity = "HIGH"
                    cat = "exfiltration"
                elif "persistence" in desc_lower or "watchdog" in desc_lower or "restart" in desc_lower:
                    severity = "HIGH"
                    cat = "persistence"
                elif "keylog" in desc_lower or "hook" in desc_lower:
                    severity = "HIGH"
                    cat = "surveillance"
                elif "process" in desc_lower or "execute" in desc_lower or "shell" in desc_lower:
                    severity = "HIGH"
                    cat = "process_execution"
                elif "encryption" in desc_lower:
                    severity = "HIGH"
                    cat = "encryption"
                elif "file" in desc_lower and ("access" in desc_lower or "enumeration" in desc_lower or "destruction" in desc_lower):
                    severity = "MEDIUM"
                    cat = "file_access"
                elif "network" in desc_lower or "socket" in desc_lower or "download" in desc_lower:
                    severity = "MEDIUM"
                    cat = "network"
                elif "reconnaissance" in desc_lower or "fingerprint" in desc_lower:
                    severity = "MEDIUM"
                    cat = "reconnaissance"
                elif "shutdown" in desc_lower or "user" in desc_lower or "scheduled" in desc_lower:
                    severity = "MEDIUM"
                    cat = "system_modification"
                elif "av evasion" in desc_lower or "disabling" in desc_lower:
                    severity = "HIGH"
                    cat = "evasion"
                elif "offensive" in desc_lower:
                    severity = "HIGH"
                    cat = "offensive_tool"

                findings.append({
                    "description": description,
                    "severity": severity,
                    "category": cat,
                    "line": line_num,
                    "context": context[:200],
                })

        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".py":
            imports_to_check = DANGEROUS_IMPORTS_PY
        elif ext in (".js", ".jse", ".wsh", ".wsf"):
            imports_to_check = DANGEROUS_IMPORTS_JS
        elif ext in (".ps1", ".psm1", ".psd1"):
            imports_to_check = DANGEROUS_IMPORTS_PS
        elif ext in (".bat", ".cmd"):
            imports_to_check = DANGEROUS_IMPORTS_BAT
        else:
            imports_to_check = DANGEROUS_IMPORTS_PY + DANGEROUS_IMPORTS_JS + DANGEROUS_IMPORTS_PS + DANGEROUS_IMPORTS_BAT

        found_imports = []
        for imp in imports_to_check:
            if imp.lower() in content.lower():
                found_imports.append(imp)

        if found_imports:
            severity = "LOW"
            if len(found_imports) >= 10:
                severity = "HIGH"
            elif len(found_imports) >= 5:
                severity = "MEDIUM"

            findings.append({
                "description": f"Dangerous imports/commands detected ({len(found_imports)})",
                "severity": severity,
                "category": "imports",
                "context": ", ".join(found_imports[:20]),
                "line": 0,
            })

        malware_naming = re.findall(
            r"(?i)(?:class|def|function|var|let|const)\s+(ransomware|ransom|encryptor|decryptor|"
            r"crypto_lock|file_locker|wiper|destroyer|stealer|grabber|keylogger|"
            r"backdoor|trojan|rat|botnet|c2|beacon|payload|dropper|loader|"
            r"extractor|harvester|scanner_|worm)",
            content
        )
        if malware_naming:
            findings.append({
                "description": f"Malware-indicative identifiers: {', '.join(set(m[0] for m in malware_naming))}",
                "severity": "HIGH",
                "category": "naming",
                "context": ", ".join(set(m[0] for m in malware_naming)),
                "line": 0,
            })

        user_dir_targets = re.findall(
            r"(?:Documents|Desktop|Pictures|Downloads|Videos|Music|OneDrive|Dropbox)",
            content
        )
        if len(user_dir_targets) >= 3:
            findings.append({
                "description": f"Multiple user data directories referenced ({len(user_dir_targets)} times)",
                "severity": "MEDIUM",
                "category": "file_access",
                "context": ", ".join(set(user_dir_targets)),
                "line": 0,
            })

    except Exception as e:
        log.error(f"Text analysis error: {e}")

    return findings


def _is_binary_data(data: bytes) -> bool:
    sample = data[:8192]
    if not sample:
        return False
    if sample[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return False
    if b"\x00" in sample and sample.count(b"\x00") / len(sample) > 0.30:
        return True
    non_text = sum(1 for b in sample if b < 7 or (14 <= b < 32 and b not in (9, 10, 13)))
    return non_text / len(sample) > 0.20


SIGNATURE_RULES = [
    {"name": "PowerShell_Obfuscation", "pattern": rb"(?:powershell|pwsh).*(?:-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})", "severity": "HIGH"},
    {"name": "Base64_Executable_Loader", "pattern": rb"(?:base64|b64decode|atob)\s*[\(\"']*[A-Za-z0-9+/=]{100,}", "severity": "HIGH"},
    {"name": "Reverse_Shell", "pattern": rb"(?:socket\.connect|\.connect\().*(?:subprocess|os\.popen|exec\(|eval\()", "severity": "CRITICAL"},
    {"name": "Registry_Persistence", "pattern": rb"(?:CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce|Winlogon\\\\Shell)", "severity": "HIGH"},
    {"name": "Process_Injection", "pattern": rb"(?:NtWriteVirtualMemory|NtCreateThreadEx|NtMapViewOfSection|QueueUserAPC|RtlCreateUserThread)", "severity": "HIGH"},
    {"name": "Keylogger_APIs", "pattern": rb"(?:GetAsyncKeyState|SetWindowsHookEx|GetKeyState|GetKeyboardState)", "severity": "HIGH"},
    {"name": "Credential_Dumping", "pattern": rb"(?:sekurlsa::|lsadump::|token::elevate|mimikatz|SAM.*SYSTEM)", "severity": "CRITICAL"},
    {"name": "Ransomware_Note", "pattern": rb"(?:your files? (?:have been|are) encrypt|pay (?:the )?ransom|bitcoin wallet|decrypt(?:ion)? (?:key|tool))", "severity": "CRITICAL"},
    {"name": "Ransomware_UI_Lock", "pattern": rb"(?:fullscreen.*True|overrideredirect.*True|topmost.*True).*(?:encrypt|lock|decrypt|ransom)", "severity": "CRITICAL"},
    {"name": "File_System_Wiper", "pattern": rb"(?:shutil\.rmtree|os\.remove.*glob|del\s+/[sf]\s+\*|format\s+[a-z]:)", "severity": "CRITICAL"},
    {"name": "Shadow_Copy_Deletion", "pattern": rb"(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no)", "severity": "CRITICAL"},
    {"name": "Discord_Exfil", "pattern": rb"discord\.com/api/webhooks", "severity": "CRITICAL"},
    {"name": "Process_Kill_Loop", "pattern": rb"(?:while\s+True|for\s+.*\s+in\s+range\(.*\)).*(?:time\.sleep|proc\.kill|taskkill|kill)", "severity": "HIGH"},
    {"name": "Wallpaper_Hijack", "pattern": rb"(?:SystemParametersInfoW|SPI_SETDESKWALLPAPER|set_desktop_wallpaper|wallpaper.*changed)", "severity": "HIGH"},
    {"name": "Timer_Countdown_Threat", "pattern": rb"(?:timedelta|countdown|time_remaining|end_time).*(?:destroy|delete|lost|gone|expired)", "severity": "CRITICAL"},
    {"name": "Shellcode_Pattern", "pattern": rb"(?:\\x[0-9a-f]{2}){32,}", "severity": "HIGH"},
    {"name": "AMSI_Bypass", "pattern": rb"(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer)", "severity": "HIGH"},
    {"name": "ETW_Patch", "pattern": rb"(?:EtwEventWrite|NtTraceControl|etw.*patch|EventRegister)", "severity": "HIGH"},
    {"name": "Anti_VM_Code", "pattern": rb"(?:VMware|VBox|VirtualBox|QEMU|SbieDll|Sandboxie|wine_get_unix)", "severity": "MEDIUM"},
    {"name": "Macro_Embed_EXE", "pattern": rb"(?:Auto_Open|Document_Open|Workbook_Open).{0,500}?(?:Shell|CreateObject|powershell|cmd\s+/c)", "severity": "HIGH"},
    {"name": "Watchdog_Process", "pattern": rb"(?:subprocess\.Popen.*sys\.argv|os\._exit|os\.kill.*os\.getpid)", "severity": "HIGH"},
    {"name": "Multi_Monitor_Attack", "pattern": rb"(?:get_monitors|secondary_monitors|multi.*monitor|screen.*resolution)", "severity": "MEDIUM"},
    {"name": "User_Data_Targeting", "pattern": rb"(?:Documents|Desktop|Pictures|Downloads|Videos|Music).*(?:os\.walk|glob|listdir|files)", "severity": "CRITICAL"},
    {"name": "File_Lock_Bypass", "pattern": rb"(?:keyboard\.block_key|keyboard\.unhook_all|disable_event|WM_DELETE_WINDOW)", "severity": "HIGH"},
    {"name": "LOLBin_Download", "pattern": rb"(?:certutil\s+-urlcache\s+-split\s+-f|bitsadmin\s+/transfer|start-bitstransfer)\s+https?://", "severity": "HIGH"},
    {"name": "Scheduled_Task_Persistence", "pattern": rb"(?:schtasks\s+/create|Register-ScheduledTask|New-ScheduledTaskAction).{0,200}?(?:powershell|cmd|\.exe|\.vbs)", "severity": "HIGH"},
    {"name": "Service_Install", "pattern": rb"(?:sc\s+create\s+\S+\s+binpath|New-Service\s+-Name|CreateServiceA)", "severity": "HIGH"},
    {"name": "Browser_Credential_Theft", "pattern": rb"(?:Login Data|Cookies\.sqlite|Local State|wallet\.dat|key4\.db|logins\.json)", "severity": "CRITICAL"},
    {"name": "Crypto_Wallet_Targeting", "pattern": rb"(?:wallet\.dat|\.electrum|Exodus\\|Metamask|keystore|seed\s*phrase)", "severity": "CRITICAL"},
    {"name": "Clipboard_Hijack", "pattern": rb"(?:Set-Clipboard|pyperclip|win32clipboard|OpenClipboard).{0,200}?(?:bc1|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})", "severity": "CRITICAL"},
    {"name": "Remote_Access_Tool", "pattern": rb"(?:ngrok|reverse_ssh|ngrok\.io|serveo\.net|localtunnel|cloudflared\s+tunnel)", "severity": "HIGH"},
    {"name": "Telegram_Exfil", "pattern": rb"api\.telegram\.org/bot[0-9]{6,}:", "severity": "CRITICAL"},
    {"name": "Ransom_Extension_Rename", "pattern": rb"(?:rename|replace)\(.{0,80}?(?:\.locked|\.encrypted|\.crypt|\.wncry|\.locky|\.zepto|\.cerber)", "severity": "CRITICAL"},
    {"name": "PDF_JS_AutoAction", "pattern": rb"/OpenAction.{0,200}?/JavaScript|/JS\s*\(.{0,120}?(?:util\.printf|app\.launchURL|this\.exportDataObject)", "severity": "HIGH"},
    {"name": "VBA_AutoExec_Macro", "pattern": rb"(?:AutoOpen|Document_Open|Workbook_Open)\s*\(\s*\).{0,400}?(?:Shell|CreateObject|Environ|Chr\()", "severity": "HIGH"},
    {"name": "Living_Off_Land_Binary", "pattern": rb"(?:mshta|regsvr32\s+/s\s+/u|rundll32\s+javascript:|msiexec\s+/q\s+/i\s+https?)", "severity": "HIGH"},
]


def run_signature_rules(filepath: str, data: bytes = None) -> list:
    matches = []
    try:
        if _looks_like_a_scanner(filepath):
            return matches

        if data is None:
            data = open(filepath, "rb").read()
        for rule in SIGNATURE_RULES:
            try:
                if re.search(rule["pattern"], data[:10_000_000], re.IGNORECASE):
                    matches.append({
                        "rule": rule["name"],
                        "severity": rule["severity"],
                    })
            except re.error:
                pass
    except Exception as e:
        log.error(f"Signature scan error: {e}")
    return matches


PDF_SUSPICIOUS = [
    (rb"/JavaScript", "PDF_JavaScript", "PDF contains JavaScript", "HIGH"),
    (rb"/JS\b", "PDF_JS_Entry", "PDF /JS entry", "MEDIUM"),
    (rb"/Launch", "PDF_Launch_Action", "PDF Launch action (runs an external program)", "CRITICAL"),
    (rb"/EmbeddedFile", "PDF_Embedded_File", "PDF embedded file attachment", "HIGH"),
    (rb"/OpenAction", "PDF_Auto_Action", "PDF auto-action executed on open", "MEDIUM"),
    (rb"/AA\b", "PDF_Additional_Actions", "PDF additional-actions trigger", "MEDIUM"),
    (rb"/RichMedia", "PDF_RichMedia", "PDF RichMedia (Flash) object", "MEDIUM"),
    (rb"/URI\s*\(https?://", "PDF_External_URI", "PDF external URI", "LOW"),
    (rb"/AcroForm.{0,2000}?/XFA", "PDF_XFA_Form", "PDF XFA form (often weaponised)", "MEDIUM"),
]

OLE_MARKERS = [
    (b"AutoOpen", "VBA AutoOpen macro entry point", "HIGH"),
    (b"Document_Open", "VBA Document_Open macro entry point", "HIGH"),
    (b"Workbook_Open", "VBA Workbook_Open macro entry point", "HIGH"),
    (b"VBAProj", "Embedded VBA project", "MEDIUM"),
    (b"_VBA_PROJECT", "Embedded VBA project stream", "MEDIUM"),
    (b"shell32", "OLE script referencing shell32", "MEDIUM"),
    (b"powershell", "OLE script referencing PowerShell", "HIGH"),
    (b"WScript.Shell", "OLE script referencing WScript.Shell", "HIGH"),
    (b"CreateObject", "OLE script using CreateObject", "MEDIUM"),
]

TRAVERSAL_RE = re.compile(rb"(?:\.\./){2,}|(?:\.\.\\){2,}")


def _read_zip_directory(data: bytes, limit: int = 4000) -> list:
    names = []
    pos = data.rfind(b"PK\x05\x06")
    if pos < 0 or pos + 22 > len(data):
        return names
    try:
        count = struct.unpack("<H", data[pos + 10:pos + 12])[0]
        cd_off = struct.unpack("<I", data[pos + 16:pos + 20])[0]
    except struct.error:
        return names
    p = cd_off
    for _ in range(min(count, limit)):
        if data[p:p + 4] != b"PK\x01\x02":
            break
        try:
            nlen = struct.unpack("<H", data[p + 28:p + 30])[0]
            elen = struct.unpack("<H", data[p + 30:p + 32])[0]
            clen = struct.unpack("<H", data[p + 32:p + 34])[0]
            csize = struct.unpack("<I", data[p + 20:p + 24])[0]
            usize = struct.unpack("<I", data[p + 24:p + 28])[0]
            method = struct.unpack("<H", data[p + 10:p + 12])[0]
            name = data[p + 46:p + 46 + nlen].decode("utf-8", errors="replace")
        except (struct.error, IndexError):
            break
        names.append({"name": name, "compressed": csize, "uncompressed": usize, "method": method})
        p += 46 + nlen + elen + clen
    return names


def inspect_container(filepath: str, data: bytes, magic: str, ext: str) -> dict:
    out = {"findings": [], "archive": None, "bomb": False,
           "embedded_executable": None, "double_extension": None, "traversal": None}
    low_ext = ext.lower()

    def add(sev, name, detail=""):
        out["findings"].append({"severity": sev, "rule": name, "detail": detail[:300]})

    base = os.path.basename(filepath)
    parts = base.split(".")
    if len(parts) >= 3:
        inner = "." + parts[-2].lower()
        if inner in (".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx", ".xls",
                     ".txt", ".mp3", ".mp4", ".zip", ".rar") and low_ext in DANGEROUS_EXTENSIONS:
            out["double_extension"] = base
            executable_exts = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js",
                               ".vbs", ".wsf", ".hta", ".lnk", ".msi", ".jar"}
            if low_ext in executable_exts:
                add("CRITICAL", "Double_Extension_Executable",
                    f"Lure extension {inner} hides an executable ({low_ext}) - classic malspam naming")
            else:
                add("HIGH", "Double_Extension", f"Lure extension {inner} hides real type {low_ext}")

    textual_exts = {".txt", ".csv", ".json", ".xml", ".html", ".md", ".log", ".ini"}
    expected = {
        ".pdf": [b"%PDF"], ".zip": [b"PK"], ".docx": [b"PK"], ".xlsx": [b"PK"],
        ".pptx": [b"PK"], ".jar": [b"PK"], ".apk": [b"PK"], ".png": [b"\x89PNG"],
        ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"], ".gif": [b"GIF8"],
        ".exe": [b"MZ"], ".dll": [b"MZ"], ".sys": [b"MZ"], ".rar": [b"Rar!"],
        ".7z": [b"7z\xbc\xaf\x27\x1c"], ".gz": [b"\x1f\x8b"],
    }
    if low_ext in expected and data:
        if not any(data.startswith(sig) for sig in expected[low_ext]):
            head = data[:12]
            if head[:2] == b"MZ" and low_ext not in (".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv"):
                out["embedded_executable"] = f"{base} is really a PE executable"
                add("CRITICAL", "Extension_Mismatch_PE", f"{low_ext} file carrying an MZ/PE header")
            else:
                add("MEDIUM", "Extension_Mismatch", f"{low_ext} header mismatch ({head!r})")
    if low_ext in textual_exts and _is_binary_data(data):
        add("MEDIUM", "Text_Extension_Binary", f"{low_ext} file contains binary data")

    if data.startswith(b"%PDF") or low_ext == ".pdf":
        if b"%%EOF" not in data[-2048:]:
            add("MEDIUM", "PDF_Truncated_Trailer", "missing %%EOF trailer")
        if data.count(b"%%EOF") > 3:
            add("MEDIUM", "PDF_Polyglot", f"multiple %%EOF markers ({data.count(b'%%EOF')})")
        if b"obj" in data and data.count(b"/Type") > 5000:
            add("LOW", "PDF_Complex", "very large object count")
        for pat, name, desc, sev in PDF_SUSPICIOUS:
            if re.search(pat, data):
                add(sev, name, desc)

    if data.startswith(b"\xd0\xcf\x11\xe0"):
        for marker, desc, sev in OLE_MARKERS:
            if marker in data:
                add(sev, "OLE_" + marker.decode(errors="replace"), desc)
        if b"vbaProject.bin" in data or b"VBA" in data[:200000]:
            add("HIGH", "OLE_VBA_Present", "macro storage present in OLE document")
    if low_ext in (".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"):
        if b"vbaProject.bin" in data:
            add("HIGH", "Office_Macro_Project", "vbaProject.bin embedded in OOXML package")

    if data.startswith(b"{\\rtf"):
        if re.search(rb"\\(?:object|objupdate|objclass)", data):
            add("HIGH", "RTF_Embedded_Object", "RTF embeds an OLE object (classic exploit vector)")
        if re.search(rb"\\objdata", data):
            add("HIGH", "RTF_ObjData", "RTF \\objdata payload")
    if low_ext == ".hta":
        add("MEDIUM", "HTA_Script", "HTML application executes script on Windows")
    if data[:4] == b"L\x00\x00\x00" and b"\\x00" not in data[:8] and low_ext == ".lnk":
        add("MEDIUM", "LNK_Shortcut", "Windows shell link")
        if re.search(rb"(?:powershell|cmd\.exe|wscript|mshta)", data, re.IGNORECASE):
            add("HIGH", "LNK_Suspicious_Target", "shortcut launches a scripting host")

    if data.startswith(b"PK") or low_ext in (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"):
        names = _read_zip_directory(data)
        if names:
            total_u = sum(n["uncompressed"] for n in names)
            total_c = max(sum(n["compressed"] for n in names), 1)
            ratio = total_u / total_c
            out["archive"] = {
                "entries": len(names),
                "uncompressed_bytes": total_u,
                "ratio": round(ratio, 1),
            }
            if ratio > 200 and total_u > 50 * 1024 * 1024:
                out["bomb"] = True
                add("HIGH", "Archive_Bomb", f"{len(names)} entries expand {ratio:.0f}x to {total_u / 1e6:.0f} MB")
            elif ratio > 1000:
                out["bomb"] = True
                add("HIGH", "Archive_Bomb", f"compression ratio {ratio:.0f}x")
            if len(names) > 20000:
                add("MEDIUM", "Archive_Huge_Entry_Count", f"{len(names)} entries")

            bad = [n["name"] for n in names
                   if ".." in n["name"].replace("\\", "/").split("/")
                   or n["name"].startswith(("/", "\\"))
                   or re.match(r"^[A-Za-z]:", n["name"])]
            if bad:
                out["traversal"] = bad[:5]
                add("HIGH", "Zip_Slip", f"path traversal entries: {', '.join(bad[:3])}")

            exe_inside = [n["name"] for n in names
                          if os.path.splitext(n["name"])[1].lower() in
                          (".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".lnk", ".jar")]
            if exe_inside:
                out["embedded_executable"] = exe_inside[:5]
                sev = "HIGH" if not low_ext.startswith(".doc") else "CRITICAL"
                add(sev, "Archive_Embedded_Executable",
                    f"executable content inside archive: {', '.join(exe_inside[:3])}")

            if any(n["method"] == 99 for n in names):
                add("MEDIUM", "Archive_Encrypted_Entries", "password-protected archive")
    elif TRAVERSAL_RE.search(data[:4096]):
        add("MEDIUM", "Path_Traversal_String", "embedded ../ sequences")

    if data.startswith(b"#!") and low_ext in DANGEROUS_EXTENSIONS - {".py", ".sh", ".bash", ".js", ".rb", ".pl"}:
        add("MEDIUM", "Shebang_In_Unexpected_Type", f"{low_ext} file starts with a shebang")

    return out


_CLAMAV_DB_CACHE = {"loaded": False, "ndb": [], "hdb": set(), "paths": []}


def _clamav_signature_files() -> list:
    candidates = []
    for base in ("/var/lib/clamav", "/usr/local/share/clamav",
                 "/var/db/clamav", os.path.join(BASE_DIR, "clamav")):
        if os.path.isdir(base):
            try:
                for fn in os.listdir(base):
                    if fn.endswith((".ndb", ".hdb", ".hsb")):
                        candidates.append(os.path.join(base, fn))
            except Exception:
                continue
    return candidates


def load_clamav_signatures(max_ndb: int = 200_000) -> dict:
    if _CLAMAV_DB_CACHE["loaded"]:
        return _CLAMAV_DB_CACHE
    _CLAMAV_DB_CACHE["loaded"] = True
    paths = _clamav_signature_files()
    _CLAMAV_DB_CACHE["paths"] = paths
    count = 0
    for path in paths:
        try:
            if path.endswith(".hdb") or path.endswith(".hsb"):
                with open(path, "r", errors="replace") as fh:
                    for line in fh:
                        h = line.split(":")[0].strip().lower()
                        if len(h) in (32, 64):
                            _CLAMAV_DB_CACHE["hdb"].add(h)
                        count += 1
            else:
                with open(path, "r", errors="replace") as fh:
                    for line in fh:
                        if not line or line.startswith("#"):
                            continue
                        parts = line.rstrip("\n").split(":")
                        if len(parts) < 4:
                            continue
                        hexsig = parts[3].strip()
                        if not hexsig or not re.fullmatch(r"[0-9a-fA-F]+", hexsig):
                            continue
                        try:
                            pattern = bytes.fromhex(hexsig)
                        except ValueError:
                            continue
                        if not pattern:
                            continue
                        _CLAMAV_DB_CACHE["ndb"].append({
                            "name": parts[0].strip(),
                            "target": parts[1].strip(),
                            "offset": parts[2].strip(),
                            "pattern": pattern,
                        })
                        count += 1
                        if len(_CLAMAV_DB_CACHE["ndb"]) >= max_ndb:
                            break
        except Exception as e:
            log.warning(f"Could not load ClamAV db {path}: {e}")
    if count:
        log.info(f"ClamAV pattern DB loaded: {count} signatures from {len(paths)} file(s)")
    return _CLAMAV_DB_CACHE


def match_clamav_signatures(filepath: str, data: bytes, hashes: dict) -> Optional[dict]:
    db = load_clamav_signatures()
    if not db["ndb"] and not db["hdb"]:
        return None

    sha256 = (hashes or {}).get("sha256", "").lower()
    md5 = (hashes or {}).get("md5", "").lower()
    if sha256 and sha256 in db["hdb"]:
        return {"matched": True, "engine": "clamav-patterns", "signature": "hdb:sha256 " + sha256,
                "severity": "CRITICAL", "method": "hash-db"}
    if md5 and md5 in db["hdb"]:
        return {"matched": True, "engine": "clamav-patterns", "signature": "hdb:md5 " + md5,
                "severity": "CRITICAL", "method": "hash-db"}

    for sig in db["ndb"]:
        if sig["pattern"] in data:
            return {"matched": True, "engine": "clamav-patterns", "signature": sig["name"],
                    "severity": "HIGH", "method": "pattern"}
    return {"matched": False, "engine": "clamav-patterns",
            "signatures_loaded": len(db["ndb"]) + len(db["hdb"])}


_YARA_CACHE = {"compiled": None, "dir": None}


def _yara_folder() -> str:
    return os.path.join(BASE_DIR, "yara_rules")


def run_yara_rules(filepath: str) -> Optional[dict]:
    if not HAS_YARA:
        return None
    rule_dir = _yara_folder()
    if not os.path.isdir(rule_dir):
        return None
    try:
        if _YARA_CACHE["compiled"] is None or _YARA_CACHE["dir"] != rule_dir:
            sources = {}
            for fn in sorted(os.listdir(rule_dir)):
                if fn.endswith((".yar", ".yara")):
                    sources[fn] = os.path.join(rule_dir, fn)
            if not sources:
                return None
            _YARA_CACHE["compiled"] = yara.compile(filepaths=sources)
            _YARA_CACHE["dir"] = rule_dir
        matches = _YARA_CACHE["compiled"].match(filepath, timeout=30)
        if not matches:
            return {"engine": "yara", "matches": []}
        out = []
        for m in matches:
            meta = getattr(m, "meta", {}) or {}
            out.append({
                "rule": m.rule,
                "severity": str(meta.get("severity", "MEDIUM")).upper(),
                "description": meta.get("description", ""),
                "tags": list(getattr(m, "tags", []) or []),
            })
        return {"engine": "yara", "matches": out}
    except Exception as e:
        log.warning(f"YARA error: {e}")
        return {"engine": "yara", "error": str(e)}


def ask_clamav_daemon(filepath: str, socket_path: str = "/run/clamav/clamd.ctl",
                      tcp_host: str = "127.0.0.1", tcp_port: int = 3310) -> Optional[dict]:
    if HAS_PYCLAMD:
        for sock in [socket_path, "/var/run/clamav/clamd.sock", "/tmp/clamd.sock"]:
            try:
                cd = pyclamd.ClamdUnixSocket(sock)
                scan_result = cd.scan_file(filepath)
                if scan_result:
                    return {
                        "engine": "clamav-daemon",
                        "infected": True,
                        "signature": scan_result[1] if isinstance(scan_result, tuple) else str(scan_result),
                        "method": f"unix://{sock}",
                    }
                return {"engine": "clamav-daemon", "infected": False, "method": f"unix://{sock}"}
            except Exception:
                pass

        try:
            cd = pyclamd.ClamdNetworkSocket(tcp_host, tcp_port)
            scan_result = cd.scan_file(filepath)
            if scan_result:
                return {
                    "engine": "clamav-daemon",
                    "infected": True,
                    "signature": scan_result[1] if isinstance(scan_result, tuple) else str(scan_result),
                    "method": f"tcp://{tcp_host}:{tcp_port}",
                }
            return {"engine": "clamav-daemon", "infected": False, "method": f"tcp://{tcp_host}:{tcp_port}"}
        except Exception:
            pass

    clamscan_path = shutil.which("clamscan")
    if clamscan_path:
        try:
            proc = subprocess.run(
                [clamscan_path, "--no-summary", "--infected", filepath],
                capture_output=True, text=True, timeout=120,
            )
            output = proc.stdout.strip()
            if output and filepath in output:
                return {
                    "engine": "clamscan-cli",
                    "infected": True,
                    "signature": output.split(":", 1)[-1].strip() if ":" in output else output,
                    "method": "cli",
                }
            return {"engine": "clamscan-cli", "infected": False, "method": "cli"}
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            log.warning("clamscan timed out")
        except Exception as e:
            log.warning(f"clamscan error: {e}")

    return None


def virustotal_lookup_hash(hash_val: str, api_key: str = "") -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    key = api_key or VT_API_KEY
    if not key:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_val}",
            headers={"x-apikey": key}, timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "engine": "virustotal-hash",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "reputation": data.get("reputation", 0),
                "names": data.get("names", [])[:3],
                "tags": data.get("tags", []),
                "last_analysis_date": data.get("last_analysis_date"),
            }
        elif resp.status_code == 404:
            return {"engine": "virustotal-hash", "status": "not_found"}
        elif resp.status_code == 429:
            log.warning("VirusTotal rate limited")
            return {"engine": "virustotal-hash", "status": "rate_limited"}
        else:
            log.warning(f"VT hash lookup returned {resp.status_code}")
            return None
    except Exception as e:
        log.warning(f"VT hash lookup failed: {e}")
        return None


def virustotal_upload_file(filepath: str, api_key: str = "") -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    key = api_key or VT_API_KEY
    if not key:
        return None

    file_size = os.path.getsize(filepath)
    if file_size > 32 * 1024 * 1024:
        log.warning(f"File too large for VT upload ({file_size / 1e6:.1f} MB > 32 MB limit)")
        return None

    try:
        url_resp = requests.get(
            "https://www.virustotal.com/api/v3/files/upload_url",
            headers={"x-apikey": key}, timeout=15,
        )
        if url_resp.status_code != 200:
            log.warning(f"VT upload_url returned {url_resp.status_code}")
            return None

        upload_url = url_resp.json().get("data", "")
        if not upload_url:
            return None

        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            upload_resp = requests.post(
                upload_url,
                headers={"x-apikey": key},
                files=files,
                timeout=120,
            )

        if upload_resp.status_code == 200:
            analysis_id = upload_resp.json().get("data", {}).get("id", "")
            result = {
                "engine": "virustotal-upload",
                "analysis_id": analysis_id,
                "status": "uploaded",
            }

            if analysis_id:
                log.info(f"VT analysis started: {analysis_id}")
                for attempt in range(12):
                    time.sleep(5)
                    try:
                        analysis_resp = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers={"x-apikey": key}, timeout=15,
                        )
                        if analysis_resp.status_code == 200:
                            adata = analysis_resp.json().get("data", {}).get("attributes", {})
                            status = adata.get("status", "")
                            if status == "completed":
                                stats = adata.get("stats", {})
                                result.update({
                                    "status": "completed",
                                    "malicious": stats.get("malicious", 0),
                                    "suspicious": stats.get("suspicious", 0),
                                    "undetected": stats.get("undetected", 0),
                                    "harmless": stats.get("harmless", 0),
                                    "total_engines": sum(stats.values()),
                                    "categories": adata.get("results", {}),
                                })
                                detections = []
                                for eng, eng_data in adata.get("results", {}).items():
                                    if eng_data.get("category") in ("malicious", "suspicious"):
                                        detections.append({
                                            "engine": eng,
                                            "result": eng_data.get("result", "unknown"),
                                            "category": eng_data.get("category"),
                                        })
                                result["top_detections"] = detections[:15]
                                break
                            else:
                                log.info(f"  VT analysis status: {status} (attempt {attempt + 1})")
                    except Exception as e:
                        log.warning(f"VT poll error: {e}")

            return result

        elif upload_resp.status_code == 429:
            return {"engine": "virustotal-upload", "status": "rate_limited"}
        else:
            log.warning(f"VT upload returned {upload_resp.status_code}: {upload_resp.text[:200]}")
            return None

    except Exception as e:
        log.warning(f"VT upload failed: {e}")
        return None


MAX_FILE_BYTES = 500_000_000
MAX_READ_FOR_CONTENT = 64 * 1024 * 1024


def scan_one_file(filepath: str, hash_db: dict = None, virus_total_key: str = "",
              skip_vt: bool = False, skip_vt_upload: bool = False,
              skip_clamav: bool = False, skip_forensics: bool = False,
              skip_patterns: bool = False, skip_yara: bool = False,
              skip_heuristics: bool = False) -> ScanResult:
    file_report = ScanResult(filepath)
    began = time.time()

    if not os.path.exists(filepath):
        file_report.errors.append("File does not exist")
        file_report.risk_level = "ERROR"
        return file_report

    try:
        file_report.file_size = os.path.getsize(filepath)
    except OSError as e:
        file_report.errors.append(str(e))
        file_report.risk_level = "ERROR"
        return file_report

    if file_report.file_size == 0:
        file_report.notes.append("Empty file - nothing to scan")
        return file_report

    if file_report.file_size > MAX_FILE_BYTES:
        file_report.errors.append("File too large (>500MB)")
        return file_report

    log.info(f"Scanning: {filepath} ({file_report.file_size / 1024:.1f} KB)")

    try:
        file_report.hashes = hash_file(filepath)
        log.info(f"  SHA256: {file_report.hashes['sha256']}")

        with open(filepath, "rb") as handle:
            first_bytes = handle.read(32)
        file_report.magic = identify_file_type(first_bytes)
        file_report.mime = guess_mime_type(filepath)

        file_report.entropy = entropy_breakdown(filepath)
        log.info(f"  Entropy: {file_report.entropy['overall']:.3f} (high_ratio: {file_report.entropy.get('high_ratio', 0):.2%})")

        suffix = os.path.splitext(filepath)[1].lower()
        if suffix in (".exe", ".dll", ".sys", ".drv", ".scr", ".cpl") and PEAnalyzer.is_pe(filepath):
            file_report.pe_info = PEAnalyzer.parse_pe(filepath)
            file_report.scan_engines.append("pe-analysis")
            if file_report.pe_info.get("suspicious_imports"):
                log.warning(f"  PE: {len(file_report.pe_info['suspicious_imports'])} sensitive imports")

        content = b""
        if file_report.file_size <= MAX_READ_FOR_CONTENT:
            with open(filepath, "rb") as handle:
                content = handle.read(MAX_READ_FOR_CONTENT)
        else:
            file_report.notes.append("File exceeds content engine cap - heuristics only")

        if not skip_heuristics:
            looks_text = (
                suffix in TEXT_EXTENSIONS
                or file_report.mime.startswith("text/")
                or (suffix in PLAIN_TEXT_EXTENSIONS and not _is_binary_data(content))
                or (suffix not in DANGEROUS_EXTENSIONS and content and not _is_binary_data(content)
                    and file_report.magic == "Unknown")
            )
            if looks_text:
                file_report.is_text_file = True
                file_report.text_findings = look_at_behaviour(filepath, content)
                if file_report.text_findings:
                    crit = sum(1 for handle in file_report.text_findings if handle["severity"] == "CRITICAL")
                    high = sum(1 for handle in file_report.text_findings if handle["severity"] == "HIGH")
                    log.warning(f"  Text analysis: {len(file_report.text_findings)} findings ({crit} CRITICAL, {high} HIGH)")

            if not file_report.is_text_file:
                file_report.text_findings = look_at_behaviour(filepath, content)
                if file_report.text_findings:
                    crit = sum(1 for handle in file_report.text_findings if handle["severity"] == "CRITICAL")
                    log.warning(f"  Behavioral analysis: {len(file_report.text_findings)} findings ({crit} CRITICAL)")

            file_report.signature_matches = run_signature_rules(filepath, content or None)
            if file_report.signature_matches:
                file_report.scan_engines.append("signatures")
                for sig in file_report.signature_matches:
                    log.warning(f"  Signature: [{sig['severity']}] {sig['rule']}")

        if not skip_forensics:
            try:
                file_report.forensics = inspect_container(filepath, content, file_report.magic, suffix)
                if file_report.forensics.get("findings"):
                    file_report.scan_engines.append("forensics")
                for handle in file_report.forensics.get("findings", []):
                    log.warning(f"  Forensics: [{handle['severity']}] {handle['rule']} - {handle['detail']}")
                if file_report.forensics.get("bomb"):
                    file_report.scan_engines.append("archive-bomb-check")
            except Exception as e:
                file_report.notes.append(f"forensics error: {e}")

        if not skip_patterns:
            try:
                pat = match_clamav_signatures(filepath, content, file_report.hashes)
                if pat is not None:
                    file_report.clamav_pattern_result = pat
                    if pat.get("signatures_loaded"):
                        file_report.scan_engines.append("clamav-patterns")
                    if pat.get("matched"):
                        file_report.scan_engines.append("clamav-patterns")
                        log.critical(f"  ClamAV pattern DB: {pat['signature']}")
            except Exception as e:
                file_report.notes.append(f"clamav-patterns error: {e}")

        if not skip_yara and HAS_YARA:
            try:
                yres = run_yara_rules(filepath)
                if yres is not None:
                    file_report.yara_result = yres
                    if yres.get("matches"):
                        file_report.scan_engines.append("yara")
                        for m in yres["matches"]:
                            log.critical(f"  YARA: {m['rule']} [{m['severity']}]")
            except Exception as e:
                file_report.notes.append(f"yara error: {e}")

        if hash_db:
            for algo in ["md5", "sha1", "sha256"]:
                if file_report.hashes.get(algo, "").lower() in hash_db.get(algo, set()):
                    file_report.hash_db_match = True
                    file_report.scan_engines.append("malware-db")
                    log.critical(f"  *** KNOWN MALWARE DATABASE MATCH ({algo.upper()}) ***")
                    break

        if not skip_clamav:
            clam_result = ask_clamav_daemon(filepath)
            if clam_result:
                file_report.clamav_result = clam_result
                file_report.scan_engines.append("clamav")
                if clam_result.get("infected"):
                    log.critical(f"  ClamAV: INFECTED - {clam_result.get('signature', 'unknown')}")
                else:
                    log.info(f"  ClamAV: Clean ({clam_result.get('method', '?')})")
            else:
                log.info("  ClamAV: unavailable")

        if not skip_vt and file_report.hashes.get("sha256"):
            vt_result = virustotal_lookup_hash(file_report.hashes["sha256"], virus_total_key)
            if vt_result:
                file_report.vt_hash_result = vt_result
                file_report.scan_engines.append("virustotal-hash")
                if vt_result.get("malicious", 0) > 0:
                    log.warning(f"  VT Hash: {vt_result['malicious']}/{vt_result.get('total_engines', '?')} detections")

        if not skip_vt_upload and not skip_vt and file_report.file_size <= 32 * 1024 * 1024:
            vt_uploaded = virustotal_upload_file(filepath, virus_total_key)
            if vt_uploaded:
                file_report.vt_upload_result = vt_uploaded
                file_report.scan_engines.append("virustotal-upload")
                if vt_uploaded.get("malicious", 0) > 0:
                    log.warning(f"  VT Upload: {vt_uploaded['malicious']}/{vt_uploaded.get('total_engines', '?')} detections")

        file_report.risk_score, file_report.risk_level = work_out_risk(file_report)

    except PermissionError as e:
        file_report.errors.append(f"Permission denied: {e}")
        file_report.risk_level = "ERROR"
    except Exception as e:
        file_report.errors.append(str(e))
        file_report.risk_level = "ERROR"
        log.error(f"  Scan error: {e}")

    file_report.scan_time = time.time() - began
    return file_report


def _load_manifest() -> dict:
    try:
        if os.path.exists(QUARANTINE_MANIFEST):
            with open(QUARANTINE_MANIFEST) as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}


def _save_manifest(m: dict):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    tmp = QUARANTINE_MANIFEST + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(m, fh, indent=2)
    os.replace(tmp, QUARANTINE_MANIFEST)


def send_to_quarantine(filepath: str, result: ScanResult = None, manifest: dict = None) -> str:
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(QUARANTINE_DIR, f"{ts}_{os.path.basename(filepath)}")
    counter = 1
    while os.path.exists(dest):
        dest = os.path.join(QUARANTINE_DIR, f"{ts}_{counter}_{os.path.basename(filepath)}")
        counter += 1
    shutil.move(filepath, dest)
    log.critical(f"Quarantined: {filepath} -> {dest}")

    if manifest is not None:
        manifest[os.path.basename(dest)] = {
            "original_path": os.path.abspath(filepath),
            "quarantined_at": datetime.datetime.now().isoformat(),
            "risk_score": result.risk_score if result else None,
            "risk_level": result.risk_level if result else None,
            "sha256": (result.hashes or {}).get("sha256") if result else None,
            "size": result.file_size if result else None,
        }
        try:
            _save_manifest(manifest)
        except Exception as e:
            log.warning(f"Could not update quarantine manifest: {e}")
    return dest


def quarantined_files() -> list:
    manifest = _load_manifest()
    items = []
    if not os.path.isdir(QUARANTINE_DIR):
        return items
    for fn in sorted(os.listdir(QUARANTINE_DIR)):
        if fn == "manifest.json":
            continue
        path = os.path.join(QUARANTINE_DIR, fn)
        if not os.path.isfile(path):
            continue
        meta = manifest.get(fn, {})
        items.append({
            "name": fn,
            "path": path,
            "size": os.path.getsize(path),
            "original_path": meta.get("original_path"),
            "quarantined_at": meta.get("quarantined_at"),
            "risk_level": meta.get("risk_level"),
            "sha256": meta.get("sha256"),
        })
    return items


def take_out_of_quarantine(name: str, target: Optional[str] = None) -> str:
    manifest = _load_manifest()
    src = os.path.join(QUARANTINE_DIR, os.path.basename(name))
    if not os.path.isfile(src):
        raise FileNotFoundError(src)
    meta = manifest.get(os.path.basename(name), {})
    dest = target or meta.get("original_path") or os.path.join(os.getcwd(), os.path.basename(name))
    if os.path.dirname(dest):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
    base, ext = os.path.splitext(dest)
    n = 1
    while os.path.exists(dest):
        dest = f"{base}.restored{n}{ext}"
        n += 1
    shutil.move(src, dest)
    manifest.pop(os.path.basename(name), None)
    try:
        _save_manifest(manifest)
    except Exception:
        pass
    log.info(f"Restored {src} -> {dest}")
    return dest


def append_to_history(label: str, results: list) -> dict:
    entry = {
        "when": datetime.datetime.now().isoformat(),
        "target": label,
        "files": len(results),
        "flagged": sum(1 for r in results if r.is_flagged()),
        "critical": sum(1 for r in results if r.risk_level == "CRITICAL"),
        "high": sum(1 for r in results if r.risk_level == "HIGH"),
        "duration": round(sum(r.scan_time for r in results), 2),
    }
    history = []
    try:
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE) as fh:
                history = json.load(fh)
            if not isinstance(history, list):
                history = []
    except Exception:
        history = []
    history.append(entry)
    try:
        tmp = SCAN_HISTORY_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(history[-200:], fh, indent=2)
        os.replace(tmp, SCAN_HISTORY_FILE)
    except Exception as e:
        log.warning(f"Could not write scan history: {e}")
    return entry


def read_history() -> list:
    try:
        if os.path.exists(SCAN_HISTORY_FILE):
            with open(SCAN_HISTORY_FILE) as fh:
                return json.load(fh)
    except Exception:
        pass
    return []


LEVEL_COLOUR = {
    "CLEAN": C.GREEN, "LOW": C.CYAN, "MEDIUM": C.YELLOW,
    "HIGH": C.RED, "CRITICAL": C.RED + C.BOLD, "ERROR": C.MAGENTA,
}
SEVERITY_COLOURS = {
    "CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
    "MEDIUM": C.YELLOW, "LOW": C.CYAN,
}


def _divider(char="─", width=76):
    print(f"{C.DIM}{char * width}{C.RESET}")


def _readable_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n:,} B"
        n /= 1024.0
    return f"{n} B"


def show_result(result: ScanResult):
    level = result.risk_level
    color = LEVEL_COLOUR.get(level, C.RESET)
    _level_badge = f"{color}{C.BOLD}[{level}]{C.RESET}"

    print(f"\n{'='*76}")
    print(f"{C.BOLD}FILE:{C.RESET}        {result.filepath}   {_level_badge}")
    print(f"{C.BOLD}SIZE:{C.RESET}        {result.file_size:,} bytes ({_readable_size(result.file_size)})")
    print(f"{C.BOLD}TYPE:{C.RESET}        {result.magic} | {result.mime} | {'Text' if result.is_text_file else 'Binary'}")
    print(f"{C.BOLD}ENTROPY:{C.RESET}     {result.entropy.get('overall', 0):.4f} (max: {result.entropy.get('max', 0):.4f})")
    if result.entropy.get("padded_chunks"):
        print(f"{C.BOLD}PADDING:{C.RESET}     {result.entropy['padded_chunks']} near-empty chunks "
              f"{C.YELLOW}(entropy dodging?){C.RESET}")
    _divider()

    print(f"{C.BOLD}HASHES:{C.RESET}")
    for k, v in result.hashes.items():
        print(f"  {k.upper():>6}: {v}")
    _divider()

    if result.pe_info:
        print(f"{C.BOLD}PE INFO:{C.RESET}")
        print(f"  Arch: {'64-bit' if result.pe_info.get('is_64bit') else '32-bit'}"
              + (f"   Compiled: {result.pe_info['timestamp']}" if result.pe_info.get("timestamp") else ""))
        for sec in result.pe_info.get("sections", []):
            flags = []
            if sec.get("executable"):
                flags.append("EXEC")
            if sec.get("writable"):
                flags.append("WRITE")
            print(f"  {sec['name']:>8}  V:{sec['virtual_size']:>10}  R:{sec['raw_size']:>10}  [{', '.join(flags)}]")
        sens = result.pe_info.get("suspicious_imports") or []
        if sens:
            print(f"  {C.YELLOW}Sensitive imports ({len(sens)}):{C.RESET} {', '.join(sens[:15])}")
        _divider()

    if result.signature_matches:
        print(f"{C.BOLD}SIGNATURE MATCHES:{C.RESET}")
        for sig in result.signature_matches:
            sc = SEVERITY_COLOURS.get(sig["severity"], C.YELLOW)
            print(f"  {sc}[{sig['severity']:>8}]{C.RESET} {sig['rule']}")
        _divider()

    if result.forensics.get("findings"):
        print(f"{C.BOLD}FILE FORENSICS:{C.RESET}")
        for f in result.forensics["findings"]:
            sc = SEVERITY_COLOURS.get(f["severity"], C.YELLOW)
            print(f"  {sc}[{f['severity']:>8}]{C.RESET} {f['rule']} {C.DIM}- {f['detail']}{C.RESET}")
        arc = result.forensics.get("archive")
        if arc:
            print(f"  {C.DIM}archive: {arc['entries']} entries, {_readable_size(arc['uncompressed_bytes'])}, "
                  f"ratio {arc['ratio']:.1f}x{C.RESET}")
        _divider()

    if result.text_findings:
        crit = sum(1 for f in result.text_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in result.text_findings if f["severity"] == "HIGH")
        med = sum(1 for f in result.text_findings if f["severity"] == "MEDIUM")
        print(f"{C.BOLD}BEHAVIORAL ANALYSIS:{C.RESET} {len(result.text_findings)} findings "
              f"({C.RED}{crit} CRITICAL{C.RESET}, {C.YELLOW}{high} HIGH{C.RESET}, {C.BLUE}{med} MEDIUM{C.RESET})")
        for f in result.text_findings[:20]:
            sc = SEVERITY_COLOURS.get(f["severity"], "")
            line_info = f" L{f['line']}" if f.get("line") else ""
            print(f"  {sc}[{f['severity']:>8}]{C.RESET} {f['description']}{C.DIM}{line_info}{C.RESET}")
            if f.get("context"):
                print(f"            {C.DIM}{f['context'][:120]}{C.RESET}")
        if len(result.text_findings) > 20:
            print(f"  {C.DIM}... and {len(result.text_findings) - 20} more findings{C.RESET}")
        _divider()

    if result.hash_db_match:
        print(f"{C.RED}{C.BOLD}*** KNOWN MALWARE DATABASE MATCH ***{C.RESET}")
        _divider()

    if result.clamav_pattern_result and result.clamav_pattern_result.get("matched"):
        print(f"{C.RED}{C.BOLD}CLAMAV PATTERN DB:{C.RESET} {result.clamav_pattern_result.get('signature')}")
        _divider()

    if result.yara_result and result.yara_result.get("matches"):
        print(f"{C.BOLD}YARA MATCHES:{C.RESET}")
        for m in result.yara_result["matches"]:
            sc = SEVERITY_COLOURS.get(m["severity"], C.YELLOW)
            print(f"  {sc}[{m['severity']:>8}]{C.RESET} {m['rule']} {C.DIM}{m.get('description', '')}{C.RESET}")
        _divider()

    if result.clamav_result:
        clam = result.clamav_result
        if clam.get("infected"):
            print(f"{C.RED}{C.BOLD}CLAMAV:{C.RESET} {C.RED}INFECTED - {clam.get('signature', 'unknown')}{C.RESET}")
        else:
            print(f"{C.GREEN}CLAMAV:{C.RESET} Clean ({clam.get('method', '?')})")
        _divider()

    if result.vt_hash_result and "malicious" in result.vt_hash_result:
        vt = result.vt_hash_result
        print(f"{C.BOLD}VT HASH LOOKUP:{C.RESET}")
        print(f"  Malicious:  {C.RED}{vt['malicious']}{C.RESET}/{vt.get('total_engines', '?')}")
        print(f"  Suspicious: {vt.get('suspicious', 0)}/{vt.get('total_engines', '?')}")
        print(f"  Undetected: {vt.get('undetected', 0)}/{vt.get('total_engines', '?')}")
        if vt.get("tags"):
            print(f"  Tags: {', '.join(vt['tags'][:10])}")
        _divider()

    if result.vt_upload_result and result.vt_upload_result.get("status") == "completed":
        vt = result.vt_upload_result
        print(f"{C.BOLD}VT FILE UPLOAD:{C.RESET}")
        print(f"  Malicious:  {C.RED}{vt.get('malicious', 0)}{C.RESET}/{vt.get('total_engines', '?')}")
        print(f"  Suspicious: {vt.get('suspicious', 0)}/{vt.get('total_engines', '?')}")
        if vt.get("top_detections"):
            print("  Top detections:")
            for d in vt["top_detections"][:10]:
                cat_color = C.RED if d["category"] == "malicious" else C.YELLOW
                print(f"    {cat_color}{d['engine']:>25}: {d['result']}{C.RESET}")
        _divider()
    elif result.vt_upload_result and result.vt_upload_result.get("status") == "uploaded":
        print(f"{C.BLUE}VT FILE UPLOAD:{C.RESET} Analysis submitted (ID: {result.vt_upload_result.get('analysis_id', '?')})")
        _divider()

    engines_str = ", ".join(dict.fromkeys(result.scan_engines)) if result.scan_engines else "heuristics-only"
    print(f"{C.BOLD}RISK SCORE:{C.RESET}  {color}{C.BOLD}{result.risk_score}/100 [{result.risk_level}]{C.RESET}")
    print(f"{C.BOLD}ENGINES:{C.RESET}     {engines_str}")
    print(f"{C.BOLD}SCAN TIME:{C.RESET}   {result.scan_time:.2f}s")
    if result.notes:
        print(f"{C.DIM}NOTES: {', '.join(result.notes)}{C.RESET}")
    if result.errors:
        print(f"{C.YELLOW}ERRORS: {', '.join(result.errors)}{C.RESET}")
    print(f"{'='*76}\n")


def show_one_line(result: ScanResult):
    color = LEVEL_COLOUR.get(result.risk_level, C.RESET)
    extra = []
    if result.signature_matches:
        extra.append(f"sig:{len(result.signature_matches)}")
    if result.text_findings:
        extra.append(f"beh:{len(result.text_findings)}")
    if result.forensics.get("findings"):
        extra.append(f"fore:{len(result.forensics['findings'])}")
    if result.clamav_pattern_result and result.clamav_pattern_result.get("matched"):
        extra.append("clamdb")
    if result.yara_result and result.yara_result.get("matches"):
        extra.append("yara")
    if result.clamav_result and result.clamav_result.get("infected"):
        extra.append("clamav")
    name = result.filepath if len(result.filepath) <= 58 else "..." + result.filepath[-55:]
    print(f"  {color}{result.risk_level:>8}{C.RESET} {result.risk_score:>3}/100 "
          f"{name:<60} {C.DIM}{','.join(extra)}{C.RESET}")


def show_totals(results: list):
    if not results:
        return
    total = len(results)
    flagged = [r for r in results if r.is_flagged()]
    counts = Counter(r.risk_level for r in results)
    total_time = sum(r.scan_time for r in results)
    total_bytes = sum(r.file_size for r in results)

    print(f"\n{'='*76}")
    print(f"{C.BOLD}SCAN SUMMARY{C.RESET}   {total} files, {_readable_size(total_bytes)}, {total_time:.1f}s")
    _divider()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR"):
        n = counts.get(level, 0)
        if not n:
            continue
        color = LEVEL_COLOUR.get(level, C.RESET)
        bar = "█" * min(40, max(1, int(40 * n / max(total, 1))))
        print(f"  {color}{level:>8}{C.RESET} {n:>5}  {color}{bar}{C.RESET}")

    if flagged:
        print(f"\n{C.BOLD}FLAGGED FILES:{C.RESET}")
        for r in sorted(flagged, key=lambda x: -x.risk_score)[:40]:
            color = LEVEL_COLOUR.get(r.risk_level, C.RESET)
            print(f"  {color}[{r.risk_level:>8}]{C.RESET} {r.risk_score:>3}/100  {r.filepath}")
        if len(flagged) > 40:
            print(f"  {C.DIM}... and {len(flagged) - 40} more{C.RESET}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}No threats detected.{C.RESET}")

    engines = sorted(set(e for r in results for e in r.scan_engines))
    print(f"\n{C.DIM}engines: {', '.join(engines) if engines else 'heuristics-only'}{C.RESET}")
    print(f"{'='*76}\n")


REPORT_TYPES = {
    "json": "full machine-readable data (everything)",
    "txt": "human-readable text report",
    "csv": "one row per file - opens in Excel/Sheets",
    "md": "markdown, good for pasting into tickets",
    "html": "self-contained dark-theme report, best for sharing",
}
DEFAULT_EXPORT_FORMAT = "html"

def _can_ask_user() -> bool:
    if UI_STATE["plain"]:
        return False
    if FROZEN and os.name == "nt":
        return True
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


def _in_the_menu() -> bool:
    return UI_STATE["interactive"] and _can_ask_user()


def ask(prompt: str, default: str = "", allow_empty: bool = True) -> str:
    try:
        raw = input(f"{C.BOLD}{prompt}{C.RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raw = ""
    if not raw:
        return default if allow_empty or default else default
    return raw


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "Y/n" if default else "y/N"
    try:
        raw = input(f"{C.BOLD}{prompt} [{suffix}]: {C.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not raw:
        return default
    return raw in ("y", "yes", "1", "true", "s", "si", "ja")


def ask_choice(prompt: str, options: list, default: str) -> str:
    print(f"{C.BOLD}{prompt}{C.RESET}")
    for i, (value, label) in enumerate(options, 1):
        marker = f"{C.GREEN}*{C.RESET}" if value == default else " "
        print(f"  {marker} {i}) {C.BOLD}{value:<6}{C.RESET} {C.DIM}{label}{C.RESET}")
    try:
        raw = input(f"  choice [1-{len(options)}] (Enter = {default}): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not raw:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1][0]
    for value, _ in options:
        if raw.lower() == value:
            return value
    return default


def make_sure_folder_exists(directory: str) -> Path:
    try:
        p = Path(os.path.expandvars(os.path.expanduser(directory))).resolve()
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".xpl01ts_write_test"
        probe.write_text("ok")
        probe.unlink()
        return p
    except Exception:
        default = DEFAULT_EXPORT_DIR
        try:
            default.mkdir(parents=True, exist_ok=True)
        except Exception:
            default = Path.cwd()
        print(f"{C.YELLOW}  ! cannot use '{directory}', falling back to {default}{C.RESET}")
        return default


def clean_file_name(name: str, default: str = "xpl01ts_report") -> str:
    name = (name or "").strip().strip('"').strip("'")
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]+", "_", name, flags=re.UNICODE).strip(" ._")
    return name or default


def build_report_data(results: list, target: str = "", level_filter: str = None) -> dict:
    flagged = [r for r in results if r.is_flagged()]
    if level_filter:
        flagged = [r for r in flagged if r.risk_level == level_filter]

    sev_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        for k, v in r.severity_counts().items():
            sev_totals[k] = sev_totals.get(k, 0) + v

    recommendations = []
    if any(r.risk_level == "CRITICAL" for r in results):
        recommendations.append("At least one file is CRITICAL: isolate the machine before opening it.")
    if any(r.hash_db_match for r in results):
        recommendations.append("A file matched the local malware hash database: quarantine it immediately.")
    if any(r.clamav_result and r.clamav_result.get("infected") for r in results):
        recommendations.append("ClamAV flagged a file: do not execute it, and update your signatures.")
    if any(r.risk_score >= 45 for r in results):
        recommendations.append("Submit HIGH/CRITICAL files to VirusTotal for a second opinion.")
    if not flagged:
        recommendations.append("No flagged files: nothing to act on from this scan.")

    return {
        "scanner": SCANNER_NAME,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "target": target or (results[0].filepath if len(results) == 1 else "multiple"),
        "total_files": len(results),
        "flagged_files": len(flagged),
        "counts": {
            "CRITICAL": sum(1 for r in results if r.risk_level == "CRITICAL"),
            "HIGH": sum(1 for r in results if r.risk_level == "HIGH"),
            "MEDIUM": sum(1 for r in results if r.risk_level == "MEDIUM"),
            "LOW": sum(1 for r in results if r.risk_level == "LOW"),
            "CLEAN": sum(1 for r in results if r.risk_level == "CLEAN"),
            "ERROR": sum(1 for r in results if r.risk_level == "ERROR"),
        },
        "severity_totals": sev_totals,
        "engines_used": sorted(set(e for r in results for e in r.scan_engines)),
        "scan_seconds": round(sum(r.scan_time for r in results), 2),
        "recommendations": recommendations,
        "results": [r.to_dict() for r in results],
    }


def _finding_rows(results: list) -> list:
    rows = []
    for r in results:
        if not r.is_flagged():
            continue
        for f in r.text_findings:
            rows.append({
                "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                "kind": "behaviour", "severity": f.get("severity"), "name": f.get("description"),
                "detail": (f.get("context") or "")[:300], "line": f.get("line", 0),
            })
        for s in r.signature_matches:
            rows.append({
                "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                "kind": "signature", "severity": s.get("severity"), "name": s.get("rule"),
                "detail": "", "line": 0,
            })
        for f in (r.forensics.get("findings") or []):
            rows.append({
                "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                "kind": "forensics", "severity": f.get("severity"), "name": f.get("rule"),
                "detail": f.get("detail", ""), "line": 0,
            })
        if r.yara_result and r.yara_result.get("matches"):
            for m in r.yara_result["matches"]:
                rows.append({
                    "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                    "kind": "yara", "severity": m.get("severity"), "name": m.get("rule"),
                    "detail": m.get("description", ""), "line": 0,
                })
        if r.hash_db_match:
            rows.append({
                "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                "kind": "hash-db", "severity": "CRITICAL", "name": "known malware hash",
                "detail": (r.hashes or {}).get("sha256", ""), "line": 0,
            })
        if r.clamav_result and r.clamav_result.get("infected"):
            rows.append({
                "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                "kind": "clamav", "severity": "CRITICAL", "name": r.clamav_result.get("signature", ""),
                "detail": r.clamav_result.get("method", ""), "line": 0,
            })
        if r.clamav_pattern_result and r.clamav_pattern_result.get("matched"):
            rows.append({
                "file": r.filepath, "risk_level": r.risk_level, "risk_score": r.risk_score,
                "kind": "clamav-db", "severity": r.clamav_pattern_result.get("severity", "HIGH"),
                "name": r.clamav_pattern_result.get("signature", ""), "detail": "", "line": 0,
            })
    return rows


def _write_json_data(payload: dict, include_files: bool, include_hashes: bool,
                 include_findings: bool, flagged_only: bool) -> str:
    data = copy.deepcopy(payload)
    if flagged_only:
        data["results"] = [r for r in data["results"] if r.get("flagged")]
    if not include_findings:
        for r in data["results"]:
            r.pop("text_findings", None)
            r.pop("signature_matches", None)
            r.pop("forensics", None)
            r.pop("yara", None)
            r.pop("clamav_patterns", None)
    if not include_hashes:
        for r in data["results"]:
            r.pop("hashes", None)
    if not include_files:
        data.pop("results", None)
        data["results_omitted"] = "file detail excluded by export options"
    return json.dumps(data, indent=2, default=str)


def _score_bar(score: int, width: int = 20) -> str:
    filled = int(round(width * min(score, 100) / 100))
    return "#" * filled + "-" * (width - filled)


def _write_text_report(payload: dict, include_files: bool, include_hashes: bool,
                include_findings: bool, flagged_only: bool) -> str:
    lines = []
    w = 78
    lines.append("=" * w)
    lines.append(f" {SCANNER_NAME.upper()} - SCAN REPORT".center(w))
    lines.append("=" * w)
    lines.append(f" Generated : {payload['generated_at']}  ({payload['generated_at_utc']})")
    lines.append(f" Scanner   : {payload['scanner']} on {payload['platform']} / python {payload['python']}")
    lines.append(f" Host      : {payload['host']}")
    lines.append(f" Target    : {payload['target']}")
    lines.append(f" Files     : {payload['total_files']} scanned, {payload['flagged_files']} flagged")
    lines.append(f" Duration  : {payload['scan_seconds']}s")
    lines.append(f" Engines   : {', '.join(payload['engines_used']) or 'none'}")
    lines.append("-" * w)
    lines.append(" VERDICTS")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR"):
        n = payload["counts"].get(level, 0)
        if n:
            lines.append(f"   {level:<9} {n:>5}  {'#' * min(40, max(1, n))}")
    lines.append("-" * w)
    st = payload["severity_totals"]
    lines.append(f" Finding severities: CRITICAL={st['CRITICAL']} HIGH={st['HIGH']} "
                 f"MEDIUM={st['MEDIUM']} LOW={st['LOW']}")
    lines.append("=" * w)

    if include_files:
        results = payload["results"]
        if flagged_only:
            results = [r for r in results if r.get("flagged")]
        lines.append("")
        lines.append(" FILE DETAIL")
        lines.append("-" * w)
        if not results:
            lines.append("   (nothing to show)")
        for r in results:
            lines.append("")
            lines.append(f" FILE      : {r['file']}")
            lines.append(f" VERDICT   : {r['risk_level']}  score {r['risk_score']}/100  "
                         f"[{_score_bar(r['risk_score'])}]")
            lines.append(f" SIZE      : {r['size_bytes']:,} bytes")
            lines.append(f" TYPE      : {r['magic']} | {r['mime']}")
            lines.append(f" ENTROPY   : {r['entropy'].get('overall', 0):.4f}  "
                         f"(max {r['entropy'].get('max', 0):.4f})")
            if include_hashes and r.get("hashes"):
                for k, v in r["hashes"].items():
                    lines.append(f"   {k.upper():<6}  : {v}")
            lines.append(f" ENGINES   : {', '.join(r['scan_engines']) or 'heuristics-only'}")
            if r.get("errors"):
                lines.append(f" ERRORS    : {'; '.join(r['errors'])}")
            if include_findings:
                if r.get("signature_matches"):
                    lines.append(" SIGNATURES:")
                    for s in r["signature_matches"]:
                        lines.append(f"   [{s['severity']:<8}] {s['rule']}")
                if r.get("forensics", {}).get("findings"):
                    lines.append(" FORENSICS:")
                    for f in r["forensics"]["findings"]:
                        lines.append(f"   [{f['severity']:<8}] {f['rule']} - {f['detail']}")
                if r.get("yara", {}) and r["yara"].get("matches"):
                    lines.append(" YARA:")
                    for m in r["yara"]["matches"]:
                        lines.append(f"   [{m['severity']:<8}] {m['rule']} {m.get('description', '')}")
                if r.get("text_findings"):
                    lines.append(f" BEHAVIOUR ({len(r['text_findings'])} findings):")
                    for f in r["text_findings"][:40]:
                        loc = f" line {f['line']}" if f.get("line") else ""
                        lines.append(f"   [{f['severity']:<8}] {f['description']}{loc}")
                        if f.get("context"):
                            lines.append(f"              {f['context'][:110]}")
                if r.get("hash_db_match"):
                    lines.append(" *** KNOWN MALWARE HASH MATCH ***")
                c = r.get("clamav")
                if c:
                    lines.append(f" CLAMAV    : "
                                 f"{'INFECTED ' + str(c.get('signature')) if c.get('infected') else 'clean'}")
                cp = r.get("clamav_patterns")
                if cp and cp.get("matched"):
                    lines.append(f" CLAMAV DB : {cp.get('signature')}")
                vt = r.get("virustotal_hash")
                if vt and "malicious" in vt:
                    lines.append(f" VIRUSTOTAL: {vt['malicious']}/{vt.get('total_engines', '?')} detections")
            lines.append("-" * w)

    lines.append("")
    lines.append(" RECOMMENDATIONS")
    for rec in payload["recommendations"]:
        lines.append(f"   * {rec}")
    lines.append("")
    lines.append("=" * w)
    lines.append(f" Generated by {SCANNER_NAME}. This report is advisory:")
    lines.append(" always verify suspicious files before acting on them.")
    lines.append("=" * w)
    return "\n".join(lines) + "\n"


def _write_csv_report(payload: dict, include_files: bool, include_hashes: bool,
                include_findings: bool, flagged_only: bool) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    results = payload["results"]
    if flagged_only:
        results = [r for r in results if r.get("flagged")]
    header = ["file", "risk_level", "risk_score", "size_bytes", "magic", "mime"]
    if include_hashes:
        header += ["md5", "sha1", "sha256"]
    header += ["engines", "findings"]
    if include_findings:
        header += ["detail_kind", "detail_severity", "detail_name", "detail_extra"]
    writer.writerow(header)

    for r in results:
        base = [r["file"], r["risk_level"], r["risk_score"], r["size_bytes"], r["magic"], r["mime"]]
        if include_hashes:
            h = r.get("hashes", {})
            base += [h.get("md5", ""), h.get("sha1", ""), h.get("sha256", "")]
        base += [",".join(r.get("scan_engines", [])), len(r.get("text_findings", []))]

        if not include_findings:
            writer.writerow(base)
            continue

        details = []
        for s in r.get("signature_matches", []):
            details.append(("signature", s["severity"], s["rule"], ""))
        for f in r.get("forensics", {}).get("findings", []):
            details.append(("forensics", f["severity"], f["rule"], f.get("detail", "")))
        for m in (r.get("yara") or {}).get("matches", []):
            details.append(("yara", m["severity"], m["rule"], m.get("description", "")))
        for f in r.get("text_findings", []):
            details.append(("behaviour", f["severity"], f["description"], f.get("context", "")))
        if r.get("hash_db_match"):
            details.append(("hash-db", "CRITICAL", "known malware hash", ""))
        if r.get("clamav", {}) and r["clamav"].get("infected"):
            details.append(("clamav", "CRITICAL", str(r["clamav"].get("signature")), ""))
        if r.get("clamav_patterns", {}) and r["clamav_patterns"].get("matched"):
            details.append(("clamav-db", r["clamav_patterns"].get("severity", "HIGH"),
                            str(r["clamav_patterns"].get("signature")), ""))
        if not details:
            writer.writerow(base + ["", "", "", ""])
        for d in details:
            writer.writerow(base + list(d))
    return buf.getvalue()


def _write_markdown_report(payload: dict, include_files: bool, include_hashes: bool,
               include_findings: bool, flagged_only: bool) -> str:
    out = []
    out.append(f"# {SCANNER_NAME} scan report")
    out.append("")
    out.append("| field | value |")
    out.append("| --- | --- |")
    out.append(f"| Generated | {payload['generated_at']} |")
    out.append(f"| Scanner | {payload['scanner']} |")
    out.append(f"| Host | `{payload['host']}` |")
    out.append(f"| Target | `{payload['target']}` |")
    out.append(f"| Files | {payload['total_files']} ({payload['flagged_files']} flagged) |")
    out.append(f"| Engines | {', '.join(payload['engines_used']) or 'none'} |")
    out.append(f"| Duration | {payload['scan_seconds']}s |")
    out.append("")
    out.append("## Verdicts")
    out.append("")
    out.append("| level | count |")
    out.append("| --- | --- |")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR"):
        n = payload["counts"].get(level, 0)
        if n:
            out.append(f"| {level} | {n} |")
    out.append("")

    if include_files:
        results = payload["results"]
        if flagged_only:
            results = [r for r in results if r.get("flagged")]
        out.append("## Files")
        for r in results:
            out.append("")
            out.append(f"### `{r['file']}`")
            out.append(f"**{r['risk_level']}** - score **{r['risk_score']}/100** - "
                       f"{r['size_bytes']:,} bytes - `{r['magic']}`")
            if include_hashes and r.get("hashes"):
                out.append("")
                out.append("```")
                for k, v in r["hashes"].items():
                    out.append(f"{k.upper()}: {v}")
                out.append("```")
            if include_findings:
                details = []
                for s in r.get("signature_matches", []):
                    details.append(f"- `{s['severity']}` signature **{s['rule']}**")
                for f in r.get("forensics", {}).get("findings", []):
                    details.append(f"- `{f['severity']}` forensics **{f['rule']}** - {f['detail']}")
                for m in (r.get("yara") or {}).get("matches", []):
                    details.append(f"- `{m['severity']}` yara **{m['rule']}**")
                for f in r.get("text_findings", []):
                    details.append(f"- `{f['severity']}` behaviour **{f['description']}**")
                if r.get("hash_db_match"):
                    details.append("- `CRITICAL` **known malware hash**")
                if details:
                    out.append("")
                    out.extend(details)
    out.append("")
    out.append("## Recommendations")
    for rec in payload["recommendations"]:
        out.append(f"- {rec}")
    out.append("")
    return "\n".join(out) + "\n"


def _write_html_report(payload: dict, include_files: bool, include_hashes: bool,
                 include_findings: bool, flagged_only: bool) -> str:
    esc = html.escape
    level_color = {
        "CRITICAL": "#ff4d4d", "HIGH": "#ff8c42", "MEDIUM": "#ffd166",
        "LOW": "#4cc9f0", "CLEAN": "#4ade80", "ERROR": "#c084fc",
    }
    results = payload["results"]
    if flagged_only:
        results = [r for r in results if r.get("flagged")]
    if not include_files:
        results = []

    def _level_badge(level):
        col = level_color.get(level, "#888")
        return (f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
                f'background:{col}22;color:{col};border:1px solid {col}66;'
                f'font-size:11px;font-weight:700;letter-spacing:.5px">{esc(str(level))}</span>')

    cards = []
    for r in results:
        details = []
        if include_findings:
            for s in r.get("signature_matches", []):
                details.append((s["severity"], "signature", s["rule"], ""))
            for f in r.get("forensics", {}).get("findings", []):
                details.append((f["severity"], "forensics", f["rule"], f.get("detail", "")))
            for m in (r.get("yara") or {}).get("matches", []):
                details.append((m["severity"], "yara", m["rule"], m.get("description", "")))
            for f in r.get("text_findings", []):
                loc = f" (line {f['line']})" if f.get("line") else ""
                details.append((f["severity"], "behaviour", f["description"] + loc, f.get("context", "")))
            if r.get("hash_db_match"):
                details.append(("CRITICAL", "hash-db", "known malware hash", ""))
            if r.get("clamav", {}) and r["clamav"].get("infected"):
                details.append(("CRITICAL", "clamav", str(r["clamav"].get("signature")), ""))
            if r.get("clamav_patterns", {}) and r["clamav_patterns"].get("matched"):
                details.append((r["clamav_patterns"].get("severity", "HIGH"), "clamav-db",
                                str(r["clamav_patterns"].get("signature")), ""))

        detail_html = ""
        if details:
            rows = "".join(
                f'<tr><td style="padding:4px 8px;white-space:nowrap">{_level_badge(d[0])}</td>'
                f'<td style="padding:4px 8px;color:#9aa4b2;white-space:nowrap">{esc(d[1])}</td>'
                f'<td style="padding:4px 8px"><code style="color:#e6edf3">{esc(d[2])}</code>'
                + (f'<div style="color:#7d8798;font-size:11px;margin-top:2px">{esc(d[3][:240])}</div>' if d[3] else "")
                + "</td></tr>"
                for d in details[:60])
            detail_html = f'<table style="width:100%;border-collapse:collapse;margin-top:10px;font-size:12px">{rows}</table>'

        hash_html = ""
        if include_hashes and r.get("hashes"):
            hash_rows = "".join(
                f'<div style="display:flex;gap:10px"><span style="color:#7d8798;width:56px">{esc(k.upper())}</span>'
                f'<code style="color:#9ecbff;word-break:break-all">{esc(v)}</code></div>'
                for k, v in r["hashes"].items())
            hash_html = f'<div style="margin-top:10px;font-size:11px;line-height:1.7">{hash_rows}</div>'

        cards.append(f"""
        <div style="background:#111823;border:1px solid #1f2a37;border-radius:10px;padding:14px 16px;margin:12px 0">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap">
            <div style="min-width:0">
              <div style="font-family:ui-monospace,Consolas,monospace;color:#e6edf3;word-break:break-all;font-size:13px">{esc(r['file'])}</div>
              <div style="color:#7d8798;font-size:11px;margin-top:4px">
                {esc(str(r['magic']))} &middot; {esc(str(r['mime']))} &middot; {r['size_bytes']:,} bytes
                &middot; entropy {r['entropy'].get('overall', 0):.2f}
              </div>
            </div>
            <div style="text-align:right;white-space:nowrap">
              {_level_badge(r['risk_level'])}
              <div style="color:#e6edf3;font-size:20px;font-weight:700;margin-top:4px">{r['risk_score']}<span style="color:#7d8798;font-size:12px">/100</span></div>
            </div>
          </div>
          {hash_html}
          {detail_html}
        </div>""")

    count_cards = "".join(
        f'<div style="flex:1;min-width:96px;background:#111823;border:1px solid #1f2a37;'
        f'border-radius:10px;padding:12px;text-align:center">'
        f'<div style="color:{level_color.get(level, "#888")};font-size:26px;font-weight:800">'
        f'{payload["counts"].get(level, 0)}</div>'
        f'<div style="color:#7d8798;font-size:11px;letter-spacing:1px">{level}</div></div>'
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"))

    recs = "".join(f'<li style="margin:4px 0">{esc(x)}</li>' for x in payload["recommendations"])
    empty = ('<div style="color:#7d8798;text-align:center;padding:24px">No file detail in this export.</div>'
             if not results else "")

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(payload['scanner'])} scan report - {esc(payload['generated_at'])}</title>
</head>
<body style="margin:0;background:#0b0f14;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
<div style="max-width:960px;margin:0 auto;padding:28px 20px 60px">
  <div style="border-bottom:1px solid #1f2a37;padding-bottom:16px;margin-bottom:20px">
    <div style="font-size:24px;font-weight:800;color:#e6edf3">{esc(payload['scanner'])} scan report</div>
    <div style="color:#7d8798;font-size:12px;margin-top:6px">
      {esc(payload['generated_at'])}
      &middot; host {esc(payload['host'])} &middot; {esc(payload['platform'])}
    </div>
    <div style="color:#9aa4b2;font-size:13px;margin-top:10px">
      Target: <code style="color:#9ecbff">{esc(payload['target'])}</code> &middot;
      {payload['total_files']} files scanned &middot; {payload['flagged_files']} flagged &middot;
      {payload['scan_seconds']}s
    </div>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">{count_cards}</div>
  <div style="background:#111823;border:1px solid #1f2a37;border-radius:10px;padding:14px 16px;margin-bottom:8px">
    <div style="color:#e6edf3;font-weight:700;margin-bottom:8px">Recommendations</div>
    <ul style="margin:0;padding-left:20px;color:#9aa4b2;font-size:13px">{recs}</ul>
  </div>
  <div style="color:#7d8798;font-size:11px;margin:16px 0 4px;letter-spacing:1px">FILES</div>
  {empty}{''.join(cards)}
  <div style="color:#4b5563;font-size:11px;margin-top:28px;border-top:1px solid #1f2a37;padding-top:12px">
    Engines: {esc(', '.join(payload['engines_used']) or 'none')}. Generated by {esc(payload['scanner'])}.
    This report is advisory - verify suspicious files before acting on them.
  </div>
</div></body></html>
"""


def render_as(fmt: str, payload: dict, include_files=True, include_hashes=True,
                  include_findings=True, flagged_only=False) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return _write_json_data(payload, include_files, include_hashes, include_findings, flagged_only)
    if fmt == "txt":
        return _write_text_report(payload, include_files, include_hashes, include_findings, flagged_only)
    if fmt == "csv":
        return _write_csv_report(payload, include_files, include_hashes, include_findings, flagged_only)
    if fmt == "md":
        return _write_markdown_report(payload, include_files, include_hashes, include_findings, flagged_only)
    if fmt == "html":
        return _write_html_report(payload, include_files, include_hashes, include_findings, flagged_only)
    raise ValueError(f"unknown report format: {fmt}")


def save_report_file(fmt: str, payload: dict, directory, name: str, include_files=True,
                 include_hashes=True, include_findings=True, flagged_only=False,
                 overwrite: bool = False) -> str:
    content = render_as(fmt, payload, include_files, include_hashes,
                            include_findings, flagged_only)
    fmt = fmt.lower()
    ext = {"json": ".json", "txt": ".txt", "csv": ".csv", "md": ".md", "html": ".html"}[fmt]
    directory = make_sure_folder_exists(str(directory))
    base = clean_file_name(name, "xpl01ts_report")
    if base.lower().endswith(ext):
        base = base[:-len(ext)]
    path = directory / (base + ext)
    if path.exists() and not overwrite:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = directory / f"{base}_{stamp}{ext}"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return str(path)


def ask_about_report(default_format: str = DEFAULT_EXPORT_FORMAT, name_hint: str = "") -> dict:
    if not ask_yes_no(f"{C.CYAN}Export a report for this scan?{C.RESET}", default=True):
        return None

    fmt = ask_choice("  Report format:", [(k, v) for k, v in REPORT_TYPES.items()],
                     default_format)

    print(f"\n{C.BOLD}  What should the report contain?{C.RESET}")
    flagged_only = ask_yes_no("    Only flagged files (skip CLEAN ones)?", default=False)
    include_files = ask_yes_no("    Include per-file detail?", default=True)
    include_hashes = ask_yes_no("    Include MD5/SHA1/SHA256/SHA512 hashes?", default=True)
    include_findings = ask_yes_no("    Include individual findings (signatures, behaviour, forensics)?",
                                  default=True)

    default_name = name_hint or f"xpl01ts_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(f"\n{C.DIM}  Leave blank to accept the default shown in brackets.{C.RESET}")
    name = ask(f"  Name the report [{default_name}]: ", default_name)
    directory = ask(f"  Save to folder [{DEFAULT_EXPORT_DIR}]: ", str(DEFAULT_EXPORT_DIR))

    return {
        "format": fmt,
        "flagged_only": flagged_only,
        "include_files": include_files,
        "include_hashes": include_hashes,
        "include_findings": include_findings,
        "name": clean_file_name(name, default_name),
        "directory": directory or str(DEFAULT_EXPORT_DIR),
    }


def offer_report(results: list, target: str = "", options: dict = None,
               auto: bool = False) -> Optional[str]:
    opts = options
    if opts is None:
        if auto or not _can_ask_user():
            opts = {
                "format": DEFAULT_EXPORT_FORMAT,
                "flagged_only": False,
                "include_files": True,
                "include_hashes": True,
                "include_findings": True,
                "name": f"xpl01ts_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "directory": str(DEFAULT_EXPORT_DIR),
            }
        else:
            opts = ask_about_report(name_hint=suggest_report_name(target))
            if opts is None:
                print(f"{C.DIM}  Export skipped.{C.RESET}")
                return None

    payload = build_report_data(results, target=target)
    try:
        path = save_report_file(
            opts["format"], payload, opts["directory"], opts["name"],
            include_files=opts.get("include_files", True),
            include_hashes=opts.get("include_hashes", True),
            include_findings=opts.get("include_findings", True),
            flagged_only=opts.get("flagged_only", False),
            overwrite=opts.get("overwrite", False),
        )
    except Exception as e:
        print(f"{C.RED}  ! export failed: {e}{C.RESET}")
        log.error(f"Export failed: {e}")
        return None

    size = os.path.getsize(path)
    print(f"{C.GREEN}{C.BOLD}  Report saved:{C.RESET} {path} {C.DIM}({_readable_size(size)}){C.RESET}")
    log.info(f"Report exported: {path} ({size} bytes, {opts['format']})")
    return path


def suggest_report_name(target: str) -> str:
    stem = target.strip().rstrip("/\\") or "scan"
    stem = os.path.basename(stem.replace("\\", "/"))
    stem = re.sub(r"[^\w.\-]+", "_", stem)[:40] or "scan"
    return f"xpl01ts_{stem}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"


def write_json_report(results: list, output_dir: str = None) -> str:
    out_dir = output_dir or REPORT_DIR
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(out_dir, f"scan_{ts}.json")

    threats = [r for r in results if r.risk_level not in ("CLEAN", "LOW")]
    report = {
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "total_files": len(results),
        "threats_found": len(threats),
        "critical": sum(1 for r in results if r.risk_level == "CRITICAL"),
        "high": sum(1 for r in results if r.risk_level == "HIGH"),
        "medium": sum(1 for r in results if r.risk_level == "MEDIUM"),
        "low": sum(1 for r in results if r.risk_level == "LOW"),
        "clean": sum(1 for r in results if r.risk_level == "CLEAN"),
        "engines_used": list(set(e for r in results for e in r.scan_engines)),
        "results": [r.to_dict() for r in results],
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info(f"Report saved: {report_path}")
    return report_path


def read_saved_report(path: str) -> tuple:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data, "imported report"
    results = data.get("results") or []
    target = data.get("target") or data.get("scan_timestamp") or "imported report"
    return results, target


def report_data_from_saved(results: list, target: str) -> dict:
    def _level_of(d):
        return d.get("risk_level", "CLEAN")

    sev_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in results:
        for k, v in (d.get("severity_counts") or {}).items():
            sev_totals[k] = sev_totals.get(k, 0) + v
    return {
        "scanner": SCANNER_NAME,
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "platform": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "target": target,
        "total_files": len(results),
        "flagged_files": sum(1 for d in results if d.get("flagged", _level_of(d) not in ("CLEAN", "LOW"))),
        "counts": {l: sum(1 for d in results if _level_of(d) == l)
                   for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR")},
        "severity_totals": sev_totals,
        "engines_used": sorted(set(e for d in results for e in (d.get("scan_engines") or []))),
        "scan_seconds": round(sum(float(d.get("scan_time_seconds") or 0) for d in results), 2),
        "recommendations": ["Imported report - re-run the scan for fresh results."],
        "results": results,
    }


TEMP_HINTS = (".tmp", ".part", ".crdownload", ".download", ".partial", "~", ".swp")


if HAS_WATCHDOG:
    class ScanHandler(FileSystemEventHandler):
        def __init__(self, hash_db, virus_total_key="", auto_quarantine=False,
                     skip_vt=False, skip_vt_upload=False, skip_clamav=False,
                     skip_forensics=False, skip_patterns=False, skip_yara=False):
            self.malware_db = hash_db
            self.vt_key = virus_total_key
            self.auto_quarantine = auto_quarantine
            self.skip_vt = skip_vt
            self.skip_vt_upload = skip_vt_upload
            self.skip_clamav = skip_clamav
            self.skip_forensics = skip_forensics
            self.skip_patterns = skip_patterns
            self.skip_yara = skip_yara
            self.results = []
            self._processing = set()
            self._recent = {}
            self.manifest = _load_manifest()
            self.count = 0
            self.skipped_duplicates = 0

        def _should_scan(self, path):
            if os.path.isdir(path) or path in self._processing:
                return False
            if "scanner.log" in path or "quarantine" in path or "reports" in path:
                return False
            if os.path.abspath(path).startswith(os.path.abspath(BASE_DIR) + os.sep):
                return False
            try:
                if os.path.exists(path) and os.path.getsize(path) == 0:
                    return False
            except OSError:
                return False
            base = os.path.basename(path).lower()
            if base.startswith(".") or base.startswith("~$"):
                return False
            if base.endswith(TEMP_HINTS):
                return False
            try:
                key = (os.path.abspath(path), os.path.getsize(path), os.path.getmtime(path))
            except OSError:
                return False
            now = time.time()
            last = self._recent.get(key)
            if last and now - last < 10:
                self.skipped_duplicates += 1
                return False
            self._recent[key] = now
            if len(self._recent) > 512:
                cutoff = now - 600
                self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
            return True

        def on_created(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

        def on_moved(self, event):
            if not getattr(event, "is_directory", False):
                self._handle(getattr(event, "dest_path", event.src_path))

        def _on_file_changed(self, path):
            if not self._should_scan(path):
                return
            self._processing.add(path)
            time.sleep(1)
            try:
                last = -1
                for _ in range(6):
                    try:
                        size = os.path.getsize(path)
                    except OSError:
                        return
                    if size == last:
                        break
                    last = size
                    time.sleep(0.8)

                if os.path.exists(path) and os.path.getsize(path) > MAX_FILE_BYTES:
                    log.info(f"Skipping oversized file: {path}")
                    return

                result = scan_one_file(path, self.malware_db, self.vt_key,
                                   self.skip_vt, self.skip_vt_upload, self.skip_clamav,
                                   self.skip_forensics, self.skip_patterns, self.skip_yara)
                self.results.append(result)
                self.count += 1
                show_result(result)
                if result.risk_score >= 75 and self.auto_quarantine:
                    dest = send_to_quarantine(path, result, self.manifest)
                    print(f"{C.RED}{C.BOLD}  -> auto-quarantined to {dest}{C.RESET}")
            except Exception as e:
                log.error(f"Error scanning {path}: {e}")
            finally:
                self._processing.discard(path)


def scan_folder(dirpath, hash_db, virus_total_key="", skip_vt=False,
                   skip_vt_upload=False, skip_clamav=False, recursive=True,
                   compact=False, skip_forensics=False, skip_patterns=False,
                   skip_yara=False, exclude=None, quiet=False):
    results = []
    dirpath = os.path.expanduser(dirpath)
    if not os.path.isdir(dirpath):
        log.error(f"Not a directory: {dirpath}")
        return results

    exclude = [os.path.abspath(os.path.expanduser(e)) for e in (exclude or [])]
    exclude.append(os.path.abspath(BASE_DIR))

    log.info(f"Scanning directory: {dirpath}")
    total = 0
    for root, dirs, files in os.walk(dirpath, followlinks=False):
        dirs[:] = [d for d in dirs
                   if not d.startswith(".")
                   and d not in ("quarantine", "reports", "__pycache__", "venv", "node_modules", ".git")]
        dirs[:] = [d for d in dirs
                   if os.path.abspath(os.path.join(root, d)) not in exclude]
        for fname in files:
            fpath = os.path.join(root, fname)
            if not os.path.isfile(fpath):
                continue
            if os.path.abspath(fpath) in exclude:
                continue
            try:
                if os.path.islink(fpath) and not os.path.exists(fpath):
                    continue
            except OSError:
                continue
            total += 1
            if not quiet and not compact:
                print(f"{C.DIM}[{total}]{C.RESET} scanning {fpath}")
            result = scan_one_file(fpath, hash_db, virus_total_key, skip_vt, skip_vt_upload, skip_clamav,
                               skip_forensics, skip_patterns, skip_yara)
            results.append(result)
            if compact:
                show_one_line(result)
            else:
                show_result(result)
        if not recursive:
            break
    if not quiet:
        show_totals(results)
    return results


def keep_watching(dirpath, hash_db, virus_total_key="", auto_quarantine=False,
                    skip_vt=False, skip_vt_upload=False, skip_clamav=False,
                    skip_forensics=False, skip_patterns=False, skip_yara=False):
    if not HAS_WATCHDOG:
        log.error("pip install watchdog")
        return

    dirpath = os.path.expanduser(dirpath)
    os.makedirs(dirpath, exist_ok=True)
    handler = ScanHandler(hash_db, virus_total_key, auto_quarantine, skip_vt, skip_vt_upload,
                          skip_clamav, skip_forensics, skip_patterns, skip_yara)
    observer = Observer()
    observer.schedule(handler, dirpath, recursive=True)
    observer.start()

    print(f"\n{'='*76}")
    print(f"{C.BOLD}{C.GREEN}  REAL-TIME FILE SCANNER ACTIVE{C.RESET}")
    print(f"  Watching: {dirpath}")
    print(f"  Engines: heuristics, forensics{', clamav-patterns' if not skip_patterns else ''}"
          f"{', clamav' if not skip_clamav else ''}{', yara' if not skip_yara else ''}"
          f"{', vt-hash' if not skip_vt else ''}{', vt-upload' if not skip_vt_upload else ''}")
    print(f"  Auto-quarantine: {'ON' if auto_quarantine else 'OFF'}")
    print("  Press Ctrl+C to stop")
    print(f"{'='*76}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log.info("Monitoring stopped.")
        if handler.results:
            write_json_report(handler.results)
            show_totals(handler.results)
    observer.join()
    return handler.results


def save_exported_report(payload: dict, opts: dict):
    try:
        path = save_report_file(
            opts["format"], payload, opts["directory"], opts["name"],
            include_files=opts.get("include_files", True),
            include_hashes=opts.get("include_hashes", True),
            include_findings=opts.get("include_findings", True),
            flagged_only=opts.get("flagged_only", False),
        )
    except Exception as e:
        print(f"{C.RED}  ! export failed: {e}{C.RESET}")
        return None
    print(f"{C.GREEN}{C.BOLD}  Report saved:{C.RESET} {path} {C.DIM}({_readable_size(os.path.getsize(path))}){C.RESET}")
    return path


def scan_this_path(path: str, hash_db: dict, quick: bool = False, compact=None) -> list:
    path = os.path.expanduser(path)
    common = dict(skip_vt=quick, skip_vt_upload=quick, skip_clamav=quick,
                  skip_forensics=False, skip_patterns=False, skip_yara=False)
    if os.path.isfile(path):
        result = scan_one_file(path, hash_db, **common)
        show_result(result)
        return [result]
    if os.path.isdir(path):
        return scan_folder(path, hash_db, compact=bool(compact), **common)
    print(f"{C.RED}Path not found: {path}{C.RESET}")
    return []


def show_hashes_menu(path: str, hash_db: dict):
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        print(f"{C.RED}Not a file: {path}{C.RESET}")
        return None
    print(f"\n{C.BOLD}Hashing:{C.RESET} {path}  ({_readable_size(os.path.getsize(path))})")
    start = time.time()
    hashes = hash_file(path)
    for k, v in hashes.items():
        print(f"  {k.upper():>6}: {v}")
    ent = entropy_breakdown(path)
    print(f"  {C.DIM}entropy: {ent['overall']:.4f}  max chunk: {ent['max']:.4f}  "
          f"chunks: {ent.get('total_chunks', 0)}  ({time.time() - start:.2f}s){C.RESET}")
    if hash_db:
        for algo in ("md5", "sha1", "sha256"):
            if hashes.get(algo) in hash_db.get(algo, set()):
                print(f"{C.RED}{C.BOLD}  *** MATCHES LOCAL MALWARE DATABASE ({algo.upper()}) ***{C.RESET}")
                break
        else:
            print(f"  {C.GREEN}not present in the local malware database{C.RESET}")
    try:
        import pyperclip
        pyperclip.copy(hashes["sha256"])
        print(f"  {C.DIM}SHA256 copied to clipboard{C.RESET}")
    except Exception:
        pass
    return hashes


def quarantine_menu(action: str, name: str = "", target: str = ""):
    items = quarantined_files()
    if action in ("list", "ls", None):
        if not items:
            print(f"{C.YELLOW}Quarantine is empty.{C.RESET}")
            return items
        print(f"\n{C.BOLD}QUARANTINE{C.RESET}  ({len(items)} items)  {QUARANTINE_DIR}")
        _divider()
        for i, it in enumerate(items, 1):
            print(f"  {i:>3}. {it['name']}")
            print(f"       {C.DIM}from: {it.get('original_path') or '?'}{C.RESET}")
            print(f"       {C.DIM}when: {it.get('quarantined_at') or '?'} | "
                  f"size: {_readable_size(it['size'])} | verdict: {it.get('risk_level') or '?'}{C.RESET}")
        _divider()
        return items

    if action == "restore":
        if not name:
            print(f"{C.RED}Provide a quarantine entry name from the list above.{C.RESET}")
            return None
        try:
            dest = take_out_of_quarantine(name, target or None)
            print(f"{C.GREEN}Restored to {dest}{C.RESET}")
            return dest
        except FileNotFoundError:
            print(f"{C.RED}No such quarantined file: {name}{C.RESET}")
            return None

    if action == "purge":
        if not items:
            print(f"{C.YELLOW}Quarantine is empty.{C.RESET}")
            return 0
        if not ask_yes_no(f"{C.RED}Permanently delete {len(items)} quarantined file(s)?{C.RESET}",
                          default=False):
            print(f"{C.DIM}Cancelled.{C.RESET}")
            return 0
        removed = 0
        for it in items:
            try:
                os.remove(it["path"])
                removed += 1
            except Exception as e:
                print(f"{C.RED}  ! {it['name']}: {e}{C.RESET}")
        try:
            _save_manifest({})
        except Exception:
            pass
        print(f"{C.GREEN}Removed {removed} file(s) from quarantine.{C.RESET}")
        return removed
    return None


def list_detection_rules():
    print(f"\n{C.BOLD}SIGNATURE RULES ({len(SIGNATURE_RULES)}){C.RESET}")
    _divider()
    for i, rule in enumerate(SIGNATURE_RULES, 1):
        sc = SEVERITY_COLOURS.get(rule["severity"], C.YELLOW)
        print(f"  {i:>3}. {sc}[{rule['severity']:>8}]{C.RESET} {rule['name']}")
    print()
    print(f"{C.BOLD}BEHAVIOUR PATTERNS ({len(BEHAVIOUR_PATTERNS)}){C.RESET}")
    _divider()
    for i, (_, desc) in enumerate(BEHAVIOUR_PATTERNS, 1):
        print(f"  {i:>3}. {desc}")
    print()
    print(f"{C.BOLD}FORENSIC CHECKS{C.RESET}: archive bomb, zip-slip, double extension, "
          f"PDF JS/Launch, macro project, RTF object, LNK target, extension mismatch")
    print(f"{C.BOLD}ENGINES AVAILABLE{C.RESET}: heuristics, signatures, pe-analysis, forensics, "
          f"clamav-patterns{', clamav' if (shutil.which('clamscan') or HAS_PYCLAMD) else ''}"
          f"{', yara' if HAS_YARA else ''}{', virustotal' if VT_API_KEY else ''}")


def show_scan_history():
    hist = read_history()
    if not hist:
        print(f"{C.YELLOW}No scan history yet.{C.RESET}")
        return hist
    print(f"\n{C.BOLD}SCAN HISTORY{C.RESET}  (last {min(len(hist), 20)} of {len(hist)})")
    _divider()
    for h in hist[-20:]:
        color = C.RED if h.get("critical") else (C.YELLOW if h.get("high") else C.GREEN)
        print(f"  {h.get('when', '?')[:19]}  {color}"
              f"{h.get('flagged', 0):>4} flagged{C.RESET}  {h.get('files', 0):>5} files  "
              f"{C.DIM}{h.get('duration', 0)}s  {h.get('target', '')[:40]}{C.RESET}")
    _divider()
    return hist


def show_diagnostics():
    print(f"\n{C.BOLD}DIAGNOSTICS{C.RESET}")
    _divider()
    print(f"  python        : {platform.python_version()} ({platform.system()} {platform.release()})")
    print(f"  executable    : {sys.executable}")
    print(f"  working dir   : {os.getcwd()}")
    print(f"  data dir      : {BASE_DIR}")
    print(f"  quarantine    : {QUARANTINE_DIR}")
    print(f"  reports       : {REPORT_DIR}")
    print(f"  hash db       : {HASH_DB_FILE}")
    print(f"  vt key set    : {'yes' if VT_API_KEY else 'no'}")
    print(f"  screen clear  : {'on' if UI_STATE.get('clear') else 'off'}  |  colour: {'on' if COLOUR_ENABLED and not UI_STATE.get('plain') else 'off'}")
    _divider()
    engines = [
        ("requests (VirusTotal)", HAS_REQUESTS),
        ("watchdog (real-time)", HAS_WATCHDOG),
        ("libmagic (MIME)", HAS_MAGIC),
        ("pyclamd (ClamAV daemon)", HAS_PYCLAMD),
        ("clamscan CLI", bool(shutil.which("clamscan"))),
        ("yara (yara-python)", HAS_YARA),
        ("clamav signature db", bool(_clamav_signature_files())),
        ("windows VT mode", UI_STATE.get("vt_ok", True)),
    ]
    for label, ok in engines:
        mark = f"{C.GREEN}ok{C.RESET}" if ok else f"{C.YELLOW}unavailable{C.RESET}"
        print(f"  {label:<26} {mark}")
    if ENGINE_NOTES:
        _divider()
        print(f"  {C.BOLD}why an engine is unavailable:{C.RESET}")
        for note in ENGINE_NOTES:
            print(f"    {C.DIM}- {note[:300]}{C.RESET}")
        yara_note = [n for n in ENGINE_NOTES if n.lower().startswith("yara")]
        if yara_note:
            print(f"\n  {C.YELLOW}YARA tips:{C.RESET}")
            print("    pip uninstall yara-python")
            print("    pip install --only-binary :all: yara-python")
            print("    or repair the Visual C++ redistributable, or just leave it off")
    elif any(ok for _, ok in engines):
        _divider()
        print(f"  {C.GREEN}no import problems detected{C.RESET}")
    _divider()



MENU = [
    ("1", "scan",     "Scan a file or folder"),
    ("2", "watch",    "Watch a folder in real time"),
    ("3", "hash",     "Hash / fingerprint a single file"),
    ("4", "export",   "Export a report from a saved scan"),
    ("5", "quarantine", "Quarantine manager (list / restore / purge)"),
    ("6", "history",  "Recent scans"),
    ("7", "rules",    "Show detection rules & engines"),
    ("d", "diagnostics", "Diagnostics (engines, paths, import problems)"),
    ("8", "db",       "Malware hash database"),
    ("9", "install",  "Check / install dependencies"),
    ("s", "settings", "Settings (screen clearing, export defaults)"),
    ("q", "quit",     "Quit"),
]


def draw_menu(hash_db: dict):
    print(f"\n{C.BOLD}{C.CYAN}  MAIN MENU{C.RESET}   "
          f"{C.DIM}hash-DB: {sum(len(v) for v in hash_db.values())} entries{C.RESET}")
    _divider()
    for key, _, label in MENU:
        if key == "q":
            continue
        print(f"   {C.BOLD}{C.WHITE}{key}{C.RESET})  {label}")
    print(f"   {C.BOLD}{C.WHITE}q{C.RESET})  {C.DIM}Quit{C.RESET}")
    _divider()


def _wait_for_enter():
    try:
        input(f"\n{C.DIM}Press Enter to return to the menu...{C.RESET}")
    except (EOFError, KeyboardInterrupt):
        print()


def scan_from_menu(hash_db: dict):
    raw = ask("  Path to scan (file or folder): ")
    if not raw:
        return
    path = os.path.expanduser(raw)
    if not os.path.exists(path):
        print(f"{C.RED}  Path not found: {path}{C.RESET}")
        return

    quick = ask_yes_no("  Quick scan (no VirusTotal, no clamd, no network)?", default=True)
    compact = False
    if os.path.isdir(path):
        compact = ask_yes_no("  Compact output (one line per file)?", default=True)
        if not ask_yes_no("  Include subfolders?", default=True):
            print(f"{C.YELLOW}  Note: full folder scans always recurse for now.{C.RESET}")

    start = time.time()
    results = scan_this_path(path, hash_db, quick=quick, compact=compact)
    if not results:
        return
    append_to_history(path, results)
    try:
        if not quick:
            write_json_report(results)
    except Exception:
        pass
    print(f"{C.DIM}  finished in {time.time() - start:.1f}s{C.RESET}")
    offer_report(results, path, None)


def watch_from_menu(hash_db: dict):
    default = os.path.join(os.path.expanduser("~"), "Downloads")
    raw = ask(f"  Folder to watch [{default}]: ", default)
    path = os.path.expanduser(raw or default)
    use_vt = ask_yes_no("  Use VirusTotal?", default=False)
    auto_q = ask_yes_no(f"  {C.RED}Auto-quarantine anything scoring 75+?{C.RESET}", default=False)
    wipe_screen()
    try:
        results = keep_watching(path, hash_db, auto_quarantine=auto_q,
                                  skip_vt=not use_vt, skip_vt_upload=not use_vt)
    except KeyboardInterrupt:
        results = []
    if results:
        try:
            path_out = write_json_report(results)
            print(f"{C.GREEN}  JSON report: {path_out}{C.RESET}")
        except Exception:
            pass
        offer_report(results, path, None)


def hash_from_menu(hash_db: dict):
    raw = ask("  File to hash: ")
    if raw:
        show_hashes_menu(os.path.expanduser(raw), hash_db)


def export_from_menu(hash_db: dict):
    default = os.path.join(REPORT_DIR)
    print(f"  {C.DIM}Point me at a saved .json report, or a file/folder to scan first.{C.RESET}")
    raw = ask(f"  Source [{default}]: ", default)
    src = os.path.expanduser(raw or default)
    if os.path.isdir(src) and os.path.abspath(src) == os.path.abspath(REPORT_DIR):
        entries = sorted([f for f in os.listdir(src) if f.endswith(".json")], reverse=True)
        if not entries:
            print(f"{C.YELLOW}  No saved reports in {src} yet.{C.RESET}")
            return
        print(f"\n  {C.BOLD}Saved reports:{C.RESET}")
        for i, fn in enumerate(entries[:15], 1):
            size = os.path.getsize(os.path.join(src, fn))
            print(f"   {i:>2}) {fn} {C.DIM}({_readable_size(size)}){C.RESET}")
        pick = ask(f"  Choose a number or press Enter for the newest [{entries[0]}]: ", entries[0])
        if pick.isdigit() and 1 <= int(pick) <= len(entries):
            src = os.path.join(src, entries[int(pick) - 1])
        elif pick in entries:
            src = os.path.join(src, pick)
        else:
            src = os.path.join(src, entries[0])

    if not os.path.isfile(src):
        print(f"{C.RED}  Not a file: {src}{C.RESET}")
        return

    if src.lower().endswith(".json"):
        try:
            dicts, target = read_saved_report(src)
        except Exception as e:
            print(f"{C.RED}  Could not read {src}: {e}{C.RESET}")
            return
        payload = report_data_from_saved(dicts, target)
        opts = ask_about_report(name_hint=suggest_report_name(target))
        if opts:
            save_exported_report(payload, opts)
    else:
        results = scan_this_path(src, hash_db, quick=True, compact=os.path.isdir(src))
        if results:
            offer_report(results, src, None)


def settings_from_menu():
    global DEFAULT_EXPORT_FORMAT
    print(f"\n{C.BOLD}  SETTINGS{C.RESET}")
    _divider()
    print(f"   1) Clear screen and re-show the banner between tasks   "
          f"[{'ON' if UI_STATE['clear'] else 'OFF'}]")
    print(f"   2) Default export format                              [{DEFAULT_EXPORT_FORMAT}]")
    print(f"   3) Default export folder                              [{DEFAULT_EXPORT_DIR}]")
    print("   4) Open quarantine / reports folders")
    _divider()
    choice = ask("  Change which setting (Enter to go back): ")
    if choice == "1":
        UI_STATE["clear"] = not UI_STATE["clear"]
        print(f"  Screen clearing is now {'ON' if UI_STATE['clear'] else 'OFF'}.")
    elif choice == "2":
        DEFAULT_EXPORT_FORMAT = ask_choice("  Default format:",
                                           [(k, v) for k, v in REPORT_TYPES.items()],
                                           DEFAULT_EXPORT_FORMAT)
        print(f"  Default format set to {DEFAULT_EXPORT_FORMAT}.")
    elif choice == "3":
        new_dir = ask(f"  Export folder [{DEFAULT_EXPORT_DIR}]: ", str(DEFAULT_EXPORT_DIR))
        p = make_sure_folder_exists(new_dir)
        print(f"  Export folder set to {p} for this session.")
    elif choice == "4":
        for label, folder in (("quarantine", QUARANTINE_DIR), ("reports", REPORT_DIR)):
            os.makedirs(folder, exist_ok=True)
            print(f"  {label}: {folder}")
    _wait_for_enter()


def main_menu_loop(hash_db: dict, start_cleared: bool = True):
    UI_STATE["interactive"] = True
    while True:
        draw_banner()
        draw_menu(hash_db)
        try:
            choice = input(f"{C.BOLD}  > {C.RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("q", "quit", "exit", "0"):
            break

        action = dict((k, a) for k, a, _ in MENU).get(choice)
        try:
            if action == "scan":
                scan_from_menu(hash_db)
            elif action == "watch":
                watch_from_menu(hash_db)
            elif action == "hash":
                hash_from_menu(hash_db)
            elif action == "export":
                export_from_menu(hash_db)
            elif action == "quarantine":
                quarantine_menu("list")
                act = ask("  (r)estore, (p)urge, Enter to go back: ").lower()
                if act.startswith("r"):
                    name = ask("  Exact entry name to restore: ")
                    if name:
                        quarantine_menu("restore", name, ask("  Restore to (blank = original): "))
                elif act.startswith("p"):
                    quarantine_menu("purge")
            elif action == "history":
                show_scan_history()
                if ask_yes_no("  Clear the history file?", default=False):
                    try:
                        os.remove(SCAN_HISTORY_FILE)
                        print(f"  {C.GREEN}History cleared.{C.RESET}")
                    except Exception as e:
                        print(f"  {C.RED}{e}{C.RESET}")
            elif action == "rules":
                list_detection_rules()
            elif action == "diagnostics":
                show_diagnostics()
            elif action == "db":
                print(f"\n{C.BOLD}Malware Hash Database:{C.RESET} {HASH_DB_FILE}")
                for a in ("md5", "sha1", "sha256"):
                    print(f"  {a.upper():>6}: {len(hash_db.get(a, set())):>6}")
                print(f"  {C.BOLD}TOTAL: {sum(len(v) for v in hash_db.values())}{C.RESET}")
                algo = ask("\n  Add a hash? (md5/sha1/sha256 or Enter to skip): ").lower()
                if algo in ("md5", "sha1", "sha256"):
                    hv = ask("  Hash value: ")
                    if hv:
                        remember_hash(hash_db, algo, hv)
                        print(f"  {C.GREEN}Added {algo.upper()}: {hv.lower()}{C.RESET}")
            elif action == "install":
                run_package_install()
            elif action == "settings":
                settings_from_menu()
            else:
                print(f"{C.YELLOW}  Unknown option '{choice}'.{C.RESET}")
                time.sleep(0.6)
                continue
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}  Interrupted.{C.RESET}")
        except Exception as e:
            print(f"{C.RED}  Error: {e}{C.RESET}")
            log.exception("menu action failed")

        _wait_for_enter()

    print(f"\n{C.CYAN}{C.BOLD}  Stay safe out there.{C.RESET}\n")
    return 0


def _back_to_menu_prompt(hash_db: dict):
    if not _can_ask_user():
        return None
    try:
        raw = input(f"\n{C.DIM}Press Enter for the main menu, or 'q' to quit: {C.RESET}")
    except (EOFError, KeyboardInterrupt):
        return None
    return raw


def main(open_menu=True):
    if not COLOUR_ENABLED:
        UI_STATE["plain"] = True
        set_colours(False)
    if "--no-clear" in sys.argv[1:] or (not FROZEN and not sys.stdout.isatty()):
        UI_STATE["clear"] = False
    CONSOLE_HANDLER.setLevel(logging.CRITICAL)
    hash_db = load_hash_db()
    if not open_menu:
        draw_banner()
        return 0
    try:
        return main_menu_loop(hash_db)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}Interrupted.{C.RESET}")
        return 130


def fix_windows_console():
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        for handle in (-11, -12):
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(k32.GetStdHandle(handle), ctypes.byref(mode)):
                k32.SetConsoleMode(k32.GetStdHandle(handle), mode.value | 0x0004)
        UI_STATE["vt_ok"] = True
    except Exception as e:
        UI_STATE["vt_ok"] = False
        ENGINE_NOTES.append(f"windows console mode: {type(e).__name__}: {e}")


def explain_crash(exc):
    lines = [
        "",
        "=" * 76,
        " the scanner hit an unexpected error and stopped",
        "=" * 76,
        f" error    : {type(exc).__name__}: {exc}",
        f" python   : {platform.python_version()} on {platform.system()} {platform.release()}",
        f" file     : {__file__}",
        " what to do:",
        "   1. re-run and open 'd' (diagnostics) to see which engine is broken",
        "   2. if it is yara:  pip uninstall yara-python",
        "                      pip install --only-binary :all: yara-python",
        "   3. the full traceback was written to scanner_crash.log",
        "=" * 76,
        "",
    ]
    print("\n".join(lines))
    try:
        with open(os.path.join(BASE_DIR, "scanner_crash.log"), "a", encoding="utf-8") as fh:
            fh.write(f"\n[{datetime.datetime.now().isoformat()}]\n")
            fh.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    except Exception:
        traceback.print_exception(type(exc), exc, exc.__traceback__)


if __name__ == "__main__":
    fix_windows_console()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except SystemExit:
        raise
    except BaseException as exc:
        explain_crash(exc)
        try:
            input("Press Enter to close...")
        except Exception:
            pass
        sys.exit(1)
