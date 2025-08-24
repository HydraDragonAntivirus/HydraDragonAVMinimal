#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HydraDragon - STRICTLY in-process libclamav integration only.

Requires the ClamAV subfolder with clamav.py module.
If the module or libclamav fails to initialize, the script exits (no fallbacks).
"""

import os
import sys
import logging
import argparse
import time
import contextlib
import json
import hashlib
import string
import threading
from typing import List, Dict, Any, Optional, Set
import argparse

# Add ClamAV subfolder to Python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLAMAV_SUBFOLDER = os.path.join(BASE_DIR, 'ClamAV')
sys.path.insert(0, CLAMAV_SUBFOLDER)

# Add local ClamAV folder to DLL search path if it exists
local_clamav = os.path.join(BASE_DIR, 'clamav')
if os.path.exists(local_clamav):
    os.add_dll_directory(local_clamav)
    current_path = os.environ.get('PATH', '')
    if local_clamav not in current_path:
        os.environ['PATH'] = local_clamav + os.pathsep + current_path
    print(f"Added local ClamAV path to search: {local_clamav}")

# ---------------- Performance monitor ----------------
class PerformanceMonitor:
    def __init__(self):
        self.timings: Dict[str, List[float]] = {}

    @contextlib.contextmanager
    def timer(self, operation_name: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            self.timings.setdefault(operation_name, []).append(elapsed)
            logging.info(f"[PERF] {operation_name}: {elapsed:.4f}s")

    def get_stats(self) -> Dict[str, Dict[str, float]]:
        return {
            op: {
                'count': len(vals),
                'total': sum(vals),
                'average': (sum(vals) / len(vals)) if vals else 0.0,
                'min': min(vals) if vals else 0.0,
                'max': max(vals) if vals else 0.0
            } for op, vals in self.timings.items()
        }

    def log_summary(self):
        logging.info("\n" + "="*60)
        logging.info("PERFORMANCE SUMMARY")
        logging.info("="*60)
        for op, stats in sorted(self.get_stats().items(), key=lambda x: x[1]['total'], reverse=True):
            logging.info(f"{op}: total={stats['total']:.4f}s avg={stats['average']:.4f}s "
                         f"count={stats['count']} min={stats['min']:.4f} max={stats['max']:.4f}")

perf_monitor = PerformanceMonitor()

# ---------------- Logging ----------------
LOG_FILE = 'antivirus.log'
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE,
                    filemode='w')
logging.captureWarnings(True)
print(f"Script starting — detailed log: {LOG_FILE}")

# ---------------- Optional third-party flags ----------------
_have_yara = False
_have_yara_x = False
_have_pefile = False
_have_chardet = False

try:
    import yara
    _have_yara = True
except Exception:
    logging.warning("yara-python not available — YARA scanning disabled.")

try:
    import yara_x
    _have_yara_x = True
except Exception:
    logging.info("yara_x not available.")

try:
    import pefile
    _have_pefile = True
except Exception:
    logging.info("pefile not available.")

try:
    import chardet
    _have_chardet = True
except Exception:
    logging.info("chardet not available; plain-text heuristics will use utf-8 fallback.")

from tqdm import tqdm

# ---------------- Paths & configuration ----------------
YARA_RULES_DIR = os.path.join(BASE_DIR, 'yara')
EXCLUDED_RULES_FILE = os.path.join(BASE_DIR, 'excluded', 'excluded_rules.txt')
ML_RESULTS_JSON = os.path.join(BASE_DIR, 'machinelearning', 'results.json')
SCAN_CACHE_FILE = os.path.join(BASE_DIR, 'scan_cache.json')

# Limits / concurrency
DEFAULT_MAX_WORKERS = max(2, (os.cpu_count() or 1))
INPROC_SEMAPHORE = threading.Semaphore(max(1, min(8, DEFAULT_MAX_WORKERS)))  # protect inproc calls if needed

# YARA order
ORDERED_YARA_FILES = [
    'yaraxtr.yrc',
    'valhalla-rules.yrc',
    'icewater.yrc',
    'machinelearning.yrc',
    'clean_rules.yrc'
]
_global_yara_compiled: Dict[str, Any] = {}

# ML globals
malicious_numeric_features: List[List[float]] = []
malicious_file_names: List[str] = []
benign_numeric_features: List[List[float]] = []
benign_file_names: List[str] = []

# Counters
malicious_file_count = 0
benign_file_count = 0
file_counter_lock = threading.Lock()

# ---------------- In-process ClamAV placeholders ----------------
CLAMAV_INPROC = None  # instance of Scanner
CLAMAV_MODULE = None  # module object

# ---------------- Utility functions ----------------
def setup_directories():
    with perf_monitor.timer("setup_directories"):
        for d in (YARA_RULES_DIR, os.path.dirname(EXCLUDED_RULES_FILE), os.path.dirname(ML_RESULTS_JSON)):
            if d and not os.path.exists(d):
                os.makedirs(d, exist_ok=True)

def calculate_md5(file_path: str) -> str:
    with perf_monitor.timer("md5_calculation"):
        h = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logging.error(f"MD5 failed for {file_path}: {e}")
            return ""

def load_scan_cache(filepath: str) -> Dict[str, Any]:
    with perf_monitor.timer("cache_load"):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logging.warning(f"Could not read cache file: {e}")
        return {}

def save_scan_cache(filepath: str, cache: Dict[str, Any]):
    with perf_monitor.timer("cache_save"):
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(cache, f, indent=4)
        except Exception as e:
            logging.error(f"Could not save cache file: {e}")

# ---------------- YARA preload ----------------
def preload_yara_rules(rules_dir: str):
    global _global_yara_compiled
    with perf_monitor.timer("yara_preload"):
        for rule_filename in ORDERED_YARA_FILES:
            rule_filepath = os.path.join(rules_dir, rule_filename)
            if not os.path.exists(rule_filepath):
                logging.info(f"YARA rule not found (skipping): {rule_filepath}")
                continue
            try:
                if rule_filename == 'yaraxtr.yrc' and _have_yara_x:
                    rules = yara_x.Rules.deserialize_from(rule_filepath)
                    _global_yara_compiled[rule_filename] = yara_x.Scanner(rules=rules)
                else:
                    if not _have_yara:
                        logging.warning(f"yara-python not available; cannot load {rule_filename}")
                        continue
                    compiled = yara.load(filepath=rule_filepath)
                    _global_yara_compiled[rule_filename] = compiled
                logging.info(f"Preloaded YARA rules: {rule_filename}")
            except Exception as e:
                logging.error(f"Failed to preload YARA rule {rule_filename}: {e}")

# ---------------- In-process ClamAV init (STRICT) ----------------
def init_inproc_clamav(dbpath: Optional[str] = None, autoreload: bool = True) -> None:
    """
    Strictly require the clamav.py module from ClamAV subfolder to be importable.
    On Windows, also checks for libclamav.dll in common installation paths.
    On any failure, exit the script — there are NO fallbacks.
    """
    global CLAMAV_INPROC, CLAMAV_MODULE
    
    # Check if ClamAV subfolder exists
    if not os.path.exists(CLAMAV_SUBFOLDER):
        logging.critical(f"ClamAV subfolder not found: {CLAMAV_SUBFOLDER}")
        print(f"ERROR: ClamAV subfolder not found at: {CLAMAV_SUBFOLDER}", file=sys.stderr)
        print("Please create a 'ClamAV' subfolder and place your clamav.py module there.", file=sys.stderr)
        sys.exit(2)
    
    # Check if clamav.py exists in the subfolder
    clamav_py_path = os.path.join(CLAMAV_SUBFOLDER, 'clamav.py')
    if not os.path.exists(clamav_py_path):
        logging.critical(f"clamav.py not found in ClamAV subfolder: {clamav_py_path}")
        print(f"ERROR: clamav.py not found at: {clamav_py_path}", file=sys.stderr)
        print("Please place your clamav.py module in the ClamAV subfolder.", file=sys.stderr)
        sys.exit(2)
    
    # Verify libclamav.dll is accessible in local folder
    local_clamav = os.path.join(BASE_DIR, 'clamav')
    libclamav_dll = os.path.join(local_clamav, 'libclamav.dll')
    if os.path.exists(libclamav_dll):
        print(f"Found libclamav.dll at: {libclamav_dll}")
    else:
        print(f"ERROR: libclamav.dll not found at: {libclamav_dll}", file=sys.stderr)
        print("Please place libclamav.dll in the 'clamav' subfolder", file=sys.stderr)
        sys.exit(2)
    
    try:
        import clamav as _clamav_pkg
        CLAMAV_MODULE = _clamav_pkg
        logging.info(f"Successfully imported clamav module from: {CLAMAV_SUBFOLDER}")
    except Exception as e:
        logging.critical(f"Required ClamAV module 'clamav.py' from ClamAV subfolder not importable: {e}")
        print(f"ERROR: Required ClamAV module 'clamav.py' from ClamAV subfolder not importable: {e}", file=sys.stderr)
        if "libclamav load failed" in str(e):
            print("\nThis error typically means:", file=sys.stderr)
            print("1. ClamAV is not installed on your system", file=sys.stderr)
            print("2. libclamav.dll is not in your PATH", file=sys.stderr)
            print("3. Install ClamAV from: https://www.clamav.net/downloads", file=sys.stderr)
        sys.exit(2)

    Scanner = getattr(CLAMAV_MODULE, 'Scanner', None)
    if Scanner is None:
        logging.critical(f"ClamAV module does not expose 'Scanner' class.")
        print(f"ERROR: ClamAV module found but no 'Scanner' class in it.", file=sys.stderr)
        sys.exit(3)

    try:
        # Try different approaches to instantiate the Scanner
        print(f"Attempting to create Scanner with dbpath: {dbpath}")
        
        # First try: with database path as string
        try:
            CLAMAV_INPROC = Scanner(dbpath, autoreload=autoreload)
            print(f"Successfully instantiated Scanner with string dbpath: {dbpath}")
        except TypeError as e:
            print(f"String dbpath failed: {e}")
            
            # Second try: with None (let Scanner find databases automatically)
            try:
                print("Trying Scanner with None dbpath...")
                CLAMAV_INPROC = Scanner(None, autoreload=autoreload)
                print("Successfully instantiated Scanner with None dbpath")
            except Exception as e2:
                print(f"None dbpath also failed: {e2}")
                
                # Third try: with no arguments
                try:
                    print("Trying Scanner with no arguments...")
                    CLAMAV_INPROC = Scanner()
                    print("Successfully instantiated Scanner with no arguments")
                except Exception as e3:
                    print(f"No arguments also failed: {e3}")
                    raise e  # Re-raise the original error
        
    except Exception as e:
        logging.critical(f"Failed to instantiate Scanner from ClamAV module: {e}")
        print(f"ERROR: Failed to instantiate Scanner from ClamAV module: {e}", file=sys.stderr)
        print(f"Attempted database path: {dbpath}", file=sys.stderr)
        print("\nTroubleshooting:", file=sys.stderr)
        print("1. Check that ClamAV database files (.cvd, .cld) exist", file=sys.stderr)
        print("2. Try specifying database path with --db-path argument", file=sys.stderr)
        print("3. Scanner may expect different argument types", file=sys.stderr)
        sys.exit(4)

    try:
        if hasattr(CLAMAV_INPROC, 'loadDB'):
            print("Loading ClamAV database...")
            with perf_monitor.timer("inproc_loadDB"):
                CLAMAV_INPROC.loadDB()
            print("ClamAV database loaded successfully.")
        else:
            print("Scanner does not have loadDB method - database may be loaded automatically.")
    except Exception as e:
        logging.critical(f"Scanner.loadDB() failed: {e}")
        print(f"ERROR: Scanner.loadDB() failed: {e}", file=sys.stderr)
        print("This might be due to:", file=sys.stderr)
        print("1. Missing or corrupt database files", file=sys.stderr)
        print("2. Incorrect database path", file=sys.stderr)
        print("3. Database files need to be updated", file=sys.stderr)
        print("\nTo download fresh databases:", file=sys.stderr)
        print("- Run 'freshclam' command if available", file=sys.stderr)
        print("- Or manually download from: https://database.clamav.net/", file=sys.stderr)
        sys.exit(5)

    logging.info("Successfully initialized in-process libclamav Scanner from ClamAV subfolder (NO fallbacks, NO timeouts).")

# ---------------- Inproc scan wrapper (NO TIMEOUT) ----------------
def _scan_inproc_blocking(path: str, engine=None) -> dict:
    try:
        if engine is None:
            raise ValueError("ClamAV engine must be loaded and passed as 'engine'")

        # Prepare arguments
        virname = CLAMAV_MODULE.c_char_p()
        bytes_scanned = CLAMAV_MODULE.c_ulong(0)
        options = CLAMAV_MODULE.cl_scan_options(general=0, parse=0, heuristic=0, mail=0, dev=0)
        path_b = path.encode('utf-8')

        # Call native cl_scanfile
        ret = CLAMAV_MODULE.libclamav.cl_scanfile(
            CLAMAV_MODULE.c_char_p(path_b),
            CLAMAV_MODULE.byref(virname),
            CLAMAV_MODULE.byref(bytes_scanned),
            engine,
            CLAMAV_MODULE.pointer(options)
        )

        # Decode virus name safely
        virus_name = None
        if virname and virname.value:
            try:
                virus_name = virname.value.decode('utf-8', errors='ignore')
            except Exception:
                virus_name = str(virname.value)

        # Interpret result
        if ret == CLAMAV_MODULE.CL_CLEAN:
            return {'status': 'clean', 'details': 'No threat found.'}
        elif ret == CLAMAV_MODULE.CL_VIRUS:
            return {'status': 'threat_found', 'details': virus_name or 'Unknown'}
        else:
            # For other error codes, fetch string description if possible
            try:
                err_msg = CLAMAV_MODULE.libclamav.cl_strerror(ret)
                if err_msg:
                    err_msg = err_msg.decode('utf-8', errors='ignore')
            except Exception:
                err_msg = f"ClamAV error code: {ret}"
            return {'status': 'error', 'details': err_msg}

    except OverflowError as e:
        logging.error(f"ClamAV scan returned OverflowError for {path}: {e}")
        return {'status': 'error', 'details': f'OverflowError: {e}'}
    except Exception as e:
        logging.exception(f"ClamAV scan failed for {path}")
        return {'status': 'error', 'details': str(e)}

def scan_file_with_clamav(path: str) -> Dict[str, Any]:
    """Direct ClamAV scan with NO timeout - blocking call."""
    with perf_monitor.timer("clamav_scan"):
        if CLAMAV_INPROC is None:
            raise RuntimeError("CLAMAV_INPROC Scanner not initialized")
        # Pass the engine instance to the scan
        return _scan_inproc_blocking(path, engine=CLAMAV_INPROC.engine)

# ---------------- DIE heuristics & YARA scanning ----------------
def is_plain_text(data: bytes, null_byte_threshold: float = 0.01, printable_threshold: float = 0.95) -> bool:
    with perf_monitor.timer("plain_text_check"):
        if not data:
            return True
        nulls = data.count(0)
        if nulls / len(data) > null_byte_threshold:
            return False
        printable = set(bytes(string.printable, 'ascii'))
        count_printable = sum(b in printable for b in data)
        if count_printable / len(data) < printable_threshold:
            return False
        enc = 'utf-8'
        if _have_chardet:
            try:
                enc = chardet.detect(data).get('encoding') or 'utf-8'
            except Exception:
                enc = 'utf-8'
        try:
            data.decode(enc)
            return True
        except Exception:
            return False

def check_file_type_with_die(file_path: str) -> str:
    with perf_monitor.timer("die_file_type_check"):
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(4096)
            if is_plain_text(sample):
                return "Binary\nFormat: plain text"
            # if detectit easy not present, return Unknown but continue scanning with ClamAV + YARA + ML
            return "Unknown"
        except FileNotFoundError:
            return "File Not Found"
        except PermissionError:
            return "Permission Denied"
        except Exception as e:
            logging.error(f"DIE check failed: {e}")
            return "Unknown"

def load_excluded_rules(filepath: str) -> Set[str]:
    with perf_monitor.timer("load_excluded_rules"):
        excluded: Set[str] = set()
        if not os.path.exists(filepath):
            return excluded
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                excluded.update(line.strip() for line in f if line.strip())
        except Exception as e:
            logging.error(f"Error reading excluded rules file: {e}")
        return excluded

def scan_file_with_yara_sequentially(file_path: str, excluded_rules: Set[str]) -> List[Dict]:
    """
    Scans a file sequentially against all preloaded YARA rules.
    Returns the first set of matched rules (stops after first hit).
    Excludes rules in excluded_rules.
    """
    with perf_monitor.timer("yara_scan_total"):
        data_content = None

        # Rules that classify file type only (not malware) → ignore
        benign_rules = {"PE_File_Magic", "ELF_File_Magic", "PDF_File_Magic"}

        for rule_filename in ORDERED_YARA_FILES:
            if rule_filename not in _global_yara_compiled:
                continue
            compiled = _global_yara_compiled[rule_filename]

            try:
                # --- yara-x mode ---
                if rule_filename == "yaraxtr.yrc" and _have_yara_x:
                    if data_content is None:
                        with perf_monitor.timer("yara_x_file_read"):
                            with open(file_path, "rb") as f:
                                data_content = f.read()
                        if not data_content:
                            continue

                    with perf_monitor.timer("yara_x_scan"):
                        scan_results = compiled.scan(data_content)

                    matched = []
                    for rule in getattr(scan_results, "matching_rules", []):
                        if rule.identifier in excluded_rules:
                            continue
                        if rule.identifier in benign_rules:
                            logging.debug(f"Ignored benign/classifier rule {rule.identifier} for {file_path}")
                            continue
                        matched.append({
                            "rule": rule.identifier,
                            "tags": [],
                            "meta": {"source": rule_filename},
                        })

                    if matched:
                        return matched

                # --- yara-python mode ---
                else:
                    if not _have_yara:
                        continue

                    with perf_monitor.timer(f"yara_match_{rule_filename}"):
                        matches = compiled.match(filepath=file_path)

                    filtered = []
                    for m in matches:
                        if m.rule in excluded_rules:
                            continue
                        if m.rule in benign_rules:
                            logging.debug(f"Ignored benign/classifier rule {m.rule} for {file_path}")
                            continue
                        filtered.append({
                            "rule": m.rule,
                            "tags": m.tags,
                            "meta": getattr(m, "meta", {}),
                        })

                    if filtered:
                        return filtered

            except Exception as e:
                logging.error(f"Error during YARA scan with {rule_filename} on {file_path}: {e}")
                continue

        return []

# ---------------- ML (PE) logic ----------------
def is_pe_file_quick(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            return f.read(2) == b'MZ'
    except Exception:
        return False

def extract_numeric_features(file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
    with perf_monitor.timer("pe_feature_extraction"):
        if not _have_pefile:
            logging.debug("pefile not available; skipping PE extraction.")
            return None
        if not is_pe_file_quick(file_path):
            return None
        try:
            pe = pefile.PE(file_path, fast_load=True)
            numeric_features = {
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            }
            pe.close()
            return numeric_features
        except Exception as e:
            logging.debug(f"PE extraction failed: {e}")
            return None

def calculate_vector_similarity(vec1: List[float], vec2: List[float]) -> float:
    import numpy as _np
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0
    a = _np.array(vec1, dtype=_np.float64)
    b = _np.array(vec2, dtype=_np.float64)
    dot = _np.dot(a, b)
    na = _np.linalg.norm(a)
    nb = _np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 1.0 if na == nb else 0.0
    cos = dot / (na * nb)
    return (cos + 1) / 2

def load_ml_definitions(filepath: str) -> bool:
    global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names
    with perf_monitor.timer("ml_definitions_load"):
        if not os.path.exists(filepath):
            logging.warning("ML definitions not found. ML disabled.")
            return False
        try:
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                ml_defs = json.load(f)
            malicious_numeric_features = []
            malicious_file_names = []
            for entry in ml_defs.get("malicious", []):
                numeric = [
                    float(entry.get("SizeOfOptionalHeader", 0)),
                    float(entry.get("MajorLinkerVersion", 0)),
                    float(entry.get("MinorLinkerVersion", 0)),
                    float(entry.get("SizeOfCode", 0)),
                    float(entry.get("SizeOfImage", 0))
                ]
                malicious_numeric_features.append(numeric)
                malicious_file_names.append(entry.get("file_info", {}).get("filename", "unknown"))
            benign_numeric_features = []
            benign_file_names = []
            for entry in ml_defs.get("benign", []):
                numeric = [
                    float(entry.get("SizeOfOptionalHeader", 0)),
                    float(entry.get("MajorLinkerVersion", 0)),
                    float(entry.get("MinorLinkerVersion", 0)),
                    float(entry.get("SizeOfCode", 0)),
                    float(entry.get("SizeOfImage", 0))
                ]
                benign_numeric_features.append(numeric)
                benign_file_names.append(entry.get("file_info", {}).get("filename", "unknown"))
            logging.info(f"Loaded ML DB: {len(malicious_numeric_features)} malicious / {len(benign_numeric_features)} benign")
            return True
        except Exception as e:
            logging.error(f"Failed to load ML definitions: {e}")
            return False

def scan_file_with_machine_learning_ai(file_path: str, threshold: float = 0.86):
    with perf_monitor.timer("ml_scan_total"):
        if not malicious_numeric_features and not benign_numeric_features:
            return False, "ML_DB_Not_Loaded", 0.0
        raw = extract_numeric_features(file_path)
        if not raw:
            return False, "Not-PE-File", 0.0
        vec = [
            float(raw.get("SizeOfOptionalHeader", 0)),
            float(raw.get("MajorLinkerVersion", 0)),
            float(raw.get("MinorLinkerVersion", 0)),
            float(raw.get("SizeOfCode", 0)),
            float(raw.get("SizeOfImage", 0)),
        ]
        best_sim = 0.0
        best_name = "Unknown"
        for mvec, name in zip(malicious_numeric_features, malicious_file_names):
            sim = calculate_vector_similarity(vec, mvec)
            if sim > best_sim:
                best_sim = sim
                best_name = name
        if best_sim >= threshold:
            return True, best_name, best_sim
        best_benign = 0.0
        for bvec in benign_numeric_features:
            sim = calculate_vector_similarity(vec, bvec)
            if sim > best_benign:
                best_benign = sim
        if best_benign > 0.93:
            return False, "Benign", best_benign
        return False, "Unknown", best_sim

# ---------------- Result logging ----------------
def log_scan_result(md5: str, result: Dict[str, Any], from_cache: bool = False):
    source = "(From Cache)" if from_cache else "(New Scan)"
    logging.info("\n" + "="*50)
    logging.info(f"SCAN RESULT {source}")
    logging.info(f"File MD5: {md5}")
    logging.info("="*50)
    status = result.get('status')
    logging.info(f"STATUS: {status}")
    logging.info("--- ClamAV ---")
    logging.info(str(result.get('clamav_result')))
    logging.info("--- YARA ---")
    logging.info(str(result.get('yara_matches')))
    logging.info("--- ML ---")
    logging.info(str(result.get('ml_result')))
    logging.info("--- Timings ---")
    for op, t in result.get('timings', {}).items():
        logging.info(f"  {op}: {t:.4f}s")
    logging.info("="*50)

# ---------------- Cache helpers ----------------
def find_cache_by_stat(cache: Dict[str, Any], stat_key: str) -> Optional[tuple]:
    for k, v in cache.items():
        if isinstance(v, dict) and v.get('_stat') == stat_key:
            return k, v
    return None

# ---------------- Per-file processing ----------------
def process_file(file_to_scan: str, excluded_yara_rules: Set[str], scanner=None):
    global malicious_file_count, benign_file_count
    start_total = time.perf_counter()
    timings: Dict[str, float] = {}

    if not os.path.exists(file_to_scan):
        logging.warning(f"File not found: {file_to_scan}")
        return

    # stat-check
    t0 = time.perf_counter()
    try:
        st = os.stat(file_to_scan)
        stat_key = f"{st.st_size}:{st.st_mtime_ns}"
    except Exception:
        stat_key = None
    timings['stat_check'] = time.perf_counter() - t0

    # load cache
    t0 = time.perf_counter()
    cache = load_scan_cache(SCAN_CACHE_FILE)
    timings['cache_load'] = time.perf_counter() - t0

    if stat_key:
        found = find_cache_by_stat(cache, stat_key)
        if found:
            md5k, cached_result = found
            cached_result['timings'] = {'cache_hit': 0.0001}
            log_scan_result(md5k, cached_result, from_cache=True)
            is_threat = (cached_result.get('clamav_result', {}).get('status') == 'threat_found' or
                         len(cached_result.get('yara_matches', [])) > 0 or
                         cached_result.get('ml_result', {}).get('is_malicious'))
            with file_counter_lock:
                if is_threat:
                    malicious_file_count += 1
                else:
                    benign_file_count += 1
            return

    # md5
    t0 = time.perf_counter()
    md5_hash = calculate_md5(file_to_scan)
    timings['md5_calculation'] = time.perf_counter() - t0
    if not md5_hash:
        return

    if md5_hash in cache:
        cached_result = cache[md5_hash]
        cached_result['timings'] = {'cache_hit': 0.0001}
        log_scan_result(md5_hash, cached_result, from_cache=True)
        is_threat = (cached_result.get('clamav_result', {}).get('status') == 'threat_found' or
                     len(cached_result.get('yara_matches', [])) > 0 or
                     cached_result.get('ml_result', {}).get('is_malicious'))
        with file_counter_lock:
            if is_threat:
                malicious_file_count += 1
            else:
                benign_file_count += 1
        return

    # size
    t0 = time.perf_counter()
    size = os.path.getsize(file_to_scan)
    timings['file_size_check'] = time.perf_counter() - t0
    if size == 0:
        result = {
            'status': 'skipped',
            'reason': 'Empty file',
            'file_type': 'Empty',
            'clamav_result': {'status': 'skipped', 'details': 'File is empty'},
            'yara_matches': [],
            'ml_result': {'is_malicious': False, 'definition': 'Skipped - Empty file', 'similarity': 0.0},
            'timings': timings,
            '_stat': stat_key
        }
        with file_counter_lock:
            benign_file_count += 1
        log_scan_result(md5_hash, result)
        cache[md5_hash] = result
        save_scan_cache(SCAN_CACHE_FILE, cache)
        return

    # file type heuristics
    t0 = time.perf_counter()
    file_type = check_file_type_with_die(file_to_scan)
    timings['file_type_detection'] = time.perf_counter() - t0

    # ClamAV scan (IN-PROC ONLY, NO TIMEOUT)
    t0 = time.perf_counter()
    clamav_res = scan_file_with_clamav(file_to_scan)
    timings['clamav_scan'] = time.perf_counter() - t0

    if clamav_res.get('status') == 'threat_found':
        result = {
            'status': 'scanned',
            'file_type': file_type,
            'clamav_result': clamav_res,
            'yara_matches': [],
            'ml_result': {'is_malicious': False, 'definition': 'Not Scanned', 'similarity': 0.0},
            'timings': timings,
            '_stat': stat_key
        }
        with file_counter_lock:
            malicious_file_count += 1
        log_scan_result(md5_hash, result)
        cache[md5_hash] = result
        save_scan_cache(SCAN_CACHE_FILE, cache)
        return

    # YARA
    t0 = time.perf_counter()
    yara_res = scan_file_with_yara_sequentially(file_to_scan, excluded_yara_rules)
    timings['yara_scan'] = time.perf_counter() - t0

    if yara_res:
        result = {
            'status': 'scanned',
            'file_type': file_type,
            'clamav_result': clamav_res,
            'yara_matches': yara_res,
            'ml_result': {'is_malicious': False, 'definition': 'Not Scanned', 'similarity': 0.0},
            'timings': timings,
            '_stat': stat_key
        }
        with file_counter_lock:
            malicious_file_count += 1
        log_scan_result(md5_hash, result)
        cache[md5_hash] = result
        save_scan_cache(SCAN_CACHE_FILE, cache)
        return

    # ML
    t0 = time.perf_counter()
    is_malicious, definition, sim = scan_file_with_machine_learning_ai(file_to_scan)
    timings['ml_scan'] = time.perf_counter() - t0
    ml_result = {'is_malicious': is_malicious, 'definition': definition, 'similarity': sim}

    if is_malicious:
        result = {
            'status': 'scanned',
            'file_type': file_type,
            'clamav_result': clamav_res,
            'yara_matches': yara_res,
            'ml_result': ml_result,
            'timings': timings,
            '_stat': stat_key
        }
        with file_counter_lock:
            malicious_file_count += 1
        log_scan_result(md5_hash, result)
        cache[md5_hash] = result
        save_scan_cache(SCAN_CACHE_FILE, cache)
        return

    # clean
    result = {
        'status': 'scanned',
        'file_type': file_type,
        'clamav_result': clamav_res,
        'yara_matches': yara_res,
        'ml_result': ml_result,
        'timings': timings,
        '_stat': stat_key
    }
    with file_counter_lock:
        benign_file_count += 1
    log_scan_result(md5_hash, result)
    cache[md5_hash] = result
    save_scan_cache(SCAN_CACHE_FILE, cache)

    total_time = time.perf_counter() - start_total
    logging.info(f"[PERF] Total file processing time for {os.path.basename(file_to_scan)}: {total_time:.4f}s")

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="HydraDragon (IN-PROCESS libclamav only, NO TIMEOUTS) + YARA + ML")
    parser.add_argument("--clear-cache", action="store_true", help="Clear scan cache")
    parser.add_argument("--show-performance", action="store_true", help="Show performance summary")
    parser.add_argument("path", nargs='?', help="Path to file or directory to scan")
    args = parser.parse_args()

    start_wall = time.perf_counter()
    setup_directories()

    if args.clear_cache and os.path.exists(SCAN_CACHE_FILE):
        os.remove(SCAN_CACHE_FILE)
        logging.info("Cache cleared.")

    # Initialize 64-bit safe in-process ClamAV
    db_abs = os.path.abspath("ClamAV/database")
    scanner = init_inproc_clamav(dbpath=db_abs, autoreload=True)

    # Load ML definitions and YARA rules
    load_ml_definitions(ML_RESULTS_JSON)
    preload_yara_rules(YARA_RULES_DIR)
    excluded_yara_rules = load_excluded_rules(EXCLUDED_RULES_FILE)

    if not args.path:
        parser.print_help()
        sys.exit(0)

    target = args.path
    if not os.path.exists(target):
        logging.critical(f"Target not found: {target}")
        print(f"ERROR: Target not found: {target}", file=sys.stderr)
        sys.exit(6)

    # Discover files
    files_to_scan: List[str] = []
    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fname in files:
                files_to_scan.append(os.path.join(root, fname))
    else:
        files_to_scan = [target]

    total_files = len(files_to_scan)
    logging.info(f"Discovered {total_files} files")

    max_workers = DEFAULT_MAX_WORKERS
    logging.info(f"Using up to {max_workers} threads for scanning")

    # Initialize counters
    global malicious_file_count, benign_file_count
    malicious_file_count = 0
    benign_file_count = 0

    # Threaded scanning (no timeout)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_file, f, excluded_yara_rules, scanner): f for f in files_to_scan}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=total_files, desc="Scanning files", unit="file"):
            fpath = futures[fut]
            try:
                result = fut.result()  # result should increment counters inside process_file
            except Exception as e:
                logging.error(f"{fpath} generated exception: {e}")

    wall_elapsed = time.perf_counter() - start_wall

    # Final summary
    print("\n" + "="*60)
    print("FINAL SCAN SUMMARY")
    print("="*60)
    print(f"Total Malicious Files Found: {malicious_file_count}")
    print(f"Total Clean Files Scanned: {benign_file_count}")
    print(f"Wall-clock Total Execution Time: {wall_elapsed:.2f}s")
    print("="*60)

    # Always show perf unless explicitly suppressed
    if args.show_performance or True:
        perf_monitor.log_summary()

if __name__ == "__main__":
    main()