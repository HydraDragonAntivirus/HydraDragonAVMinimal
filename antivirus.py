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
import inspect
import numpy as np

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

def extract_yarax_match_details(rule, source):
    """Extract match details from YARA-X rule match."""
    return {
        "rule": rule.identifier,
        "tags": getattr(rule, 'tags', []),
        "meta": {"source": source},
    }

def scan_file_with_yara_sequentially(file_path: str, excluded_rules: Set[str]) -> List[Dict]:
    """
    Scans a file sequentially against all preloaded YARA rules using threading for YARA-X.
    Returns the first set of matched rules (stops after first hit).
    Excludes rules in excluded_rules.
    """
    with perf_monitor.timer("yara_scan_total"):
        data_content = None
        results_lock = threading.Lock()
        results = {
            'matched_rules': [],
            'matched_results': []
        }

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

                    # Thread worker for yaraxtr_rule scanning (YARA-X)
                    def yaraxtr_rule_worker():
                        try:
                            if compiled:
                                scan_results = compiled.scan(data_content)
                                local_matched_rules = []
                                local_matched_results = []

                                # Iterate through matching rules
                                for rule in getattr(scan_results, "matching_rules", []):
                                    if rule.identifier not in excluded_rules:
                                        local_matched_rules.append(rule.identifier)
                                        match_details = extract_yarax_match_details(rule, rule_filename)
                                        local_matched_results.append(match_details)
                                    else:
                                        logging.info(f"Rule {rule.identifier} is excluded from {rule_filename}.")

                                # Update shared results
                                with results_lock:
                                    results['matched_rules'].extend(local_matched_rules)
                                    results['matched_results'].extend(local_matched_results)
                            else:
                                logging.error(f"{rule_filename} is not defined.")
                        except Exception as e:
                            logging.error(f"Error scanning with {rule_filename}: {e}")

                    # Run the worker in a thread
                    thread = threading.Thread(target=yaraxtr_rule_worker)
                    thread.start()
                    thread.join()  # Wait for completion

                    # Check if we found matches
                    if results['matched_results']:
                        return results['matched_results']

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

# --- PE Analysis and Feature Extraction Functions (NEWLY UPDATED) ---

def extract_infos(file_path, rank=None):
    """Extract information about file"""
    file_name = os.path.basename(file_path)
    if rank is not None:
        return {'file_name': file_name, 'numeric_tag': rank}
    else:
        return {'file_name': file_name}

def calculate_entropy(data: list) -> float:
    """Calculate Shannon entropy of data (provided as a list of integers)."""
    if not data:
        return 0.0

    total_items = len(data)
    value_counts = [data.count(i) for i in range(256)]  # Count occurrences of each byte (0-255)

    entropy = 0.0
    for count in value_counts:
        if count > 0:
            p_x = count / total_items
            entropy -= p_x * np.log2(p_x)

    return entropy

def get_callback_addresses(pe: pefile.PE, address_of_callbacks: int) -> List[int]:
    """Retrieve callback addresses from the TLS directory."""
    try:
        callback_addresses = []
        # Read callback addresses from the memory-mapped file
        while True:
            callback_address = pe.get_dword_at_rva(address_of_callbacks - pe.OPTIONAL_HEADER.ImageBase)
            if callback_address == 0:
                break  # End of callback list
            callback_addresses.append(callback_address)
            address_of_callbacks += 4  # Move to the next address (4 bytes for DWORD)

        return callback_addresses
    except Exception as e:
        logging.error(f"Error retrieving TLS callback addresses: {e}")
        return []

def analyze_tls_callbacks(pe: pefile.PE) -> Dict[str, Any]:
    """Analyze TLS (Thread Local Storage) callbacks and extract relevant details."""
    try:
        tls_callbacks = {}
        # Check if the PE file has a TLS directory
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            tls = pe.DIRECTORY_ENTRY_TLS.struct
            tls_callbacks = {
                'start_address_raw_data': tls.StartAddressOfRawData,
                'end_address_raw_data': tls.EndAddressOfRawData,
                'address_of_index': tls.AddressOfIndex,
                'address_of_callbacks': tls.AddressOfCallBacks,
                'size_of_zero_fill': tls.SizeOfZeroFill,
                'characteristics': tls.Characteristics,
                'callbacks': []
            }

            # If there are callbacks, extract their addresses
            if tls.AddressOfCallBacks:
                callback_array = get_callback_addresses(pe, tls.AddressOfCallBacks)
                if callback_array:
                    tls_callbacks['callbacks'] = callback_array

        return tls_callbacks
    except Exception as e:
        logging.error(f"Error analyzing TLS callbacks: {e}")
        return {}

def analyze_dos_stub(pe) -> Dict[str, Any]:
    """Analyze DOS stub program."""
    try:
        dos_stub = {
            'exists': False,
            'size': 0,
            'entropy': 0.0,
        }

        if hasattr(pe, 'DOS_HEADER'):
            stub_offset = pe.DOS_HEADER.e_lfanew - 64  # Typical DOS stub starts after DOS header
            if stub_offset > 0:
                dos_stub_data = pe.__data__[64:pe.DOS_HEADER.e_lfanew]
                if dos_stub_data:
                    dos_stub['exists'] = True
                    dos_stub['size'] = len(dos_stub_data)
                    dos_stub['entropy'] = calculate_entropy(list(dos_stub_data))

        return dos_stub
    except Exception as ex:
        logging.error(f"Error analyzing DOS stub: {ex}")
        return {}

def analyze_certificates(pe) -> Dict[str, Any]:
    """Analyze security certificates."""
    try:
        cert_info = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
            cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size

            # Extract certificate attributes if available
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                info = pe.VS_FIXEDFILEINFO[0] # VS_FIXEDFILEINFO is a list
                cert_info['fixed_file_info'] = {
                    'signature': info.Signature,
                    'struct_version': info.StrucVersion,
                    'file_version': f"{info.FileVersionMS >> 16}.{info.FileVersionMS & 0xFFFF}.{info.FileVersionLS >> 16}.{info.FileVersionLS & 0xFFFF}",
                    'product_version': f"{info.ProductVersionMS >> 16}.{info.ProductVersionMS & 0xFFFF}.{info.ProductVersionLS >> 16}.{info.ProductVersionLS & 0xFFFF}",
                    'file_flags': info.FileFlags,
                    'file_os': info.FileOS,
                    'file_type': info.FileType,
                    'file_subtype': info.FileSubtype,
                }

        return cert_info
    except Exception as e:
        logging.error(f"Error analyzing certificates: {e}")
        return {}

def analyze_delay_imports(pe) -> List[Dict[str, Any]]:
    """Analyze delay-load imports with error handling for missing attributes."""
    try:
        delay_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                imports = []
                for imp in entry.imports:
                    import_info = {
                        'name': imp.name.decode() if imp.name else None,
                        'address': imp.address,
                        'ordinal': imp.ordinal,
                    }
                    imports.append(import_info)

                delay_import = {
                    'dll': entry.dll.decode() if entry.dll else None,
                    'attributes': getattr(entry.struct, 'Attributes', None),
                    'name': getattr(entry.struct, 'Name', None),
                    'handle': getattr(entry.struct, 'Handle', None),
                    'iat': getattr(entry.struct, 'IAT', None),
                    'bound_iat': getattr(entry.struct, 'BoundIAT', None),
                    'unload_iat': getattr(entry.struct, 'UnloadIAT', None),
                    'timestamp': getattr(entry.struct, 'TimeDateStamp', None),
                    'imports': imports
                }
                delay_imports.append(delay_import)

        return delay_imports
    except Exception as e:
        logging.error(f"Error analyzing delay imports: {e}")
        return []

def analyze_load_config(pe) -> Dict[str, Any]:
    """Analyze load configuration."""
    try:
        load_config = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
            config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
            load_config = {
                'size': config.Size,
                'timestamp': config.TimeDateStamp,
                'major_version': config.MajorVersion,
                'minor_version': config.MinorVersion,
                'global_flags_clear': config.GlobalFlagsClear,
                'global_flags_set': config.GlobalFlagsSet,
                'critical_section_default_timeout': config.CriticalSectionDefaultTimeout,
                'decommit_free_block_threshold': config.DeCommitFreeBlockThreshold,
                'decommit_total_free_threshold': config.DeCommitTotalFreeThreshold,
                'security_cookie': getattr(config, 'SecurityCookie', None), # Use getattr for safety
                'se_handler_table': getattr(config, 'SEHandlerTable', None),
                'se_handler_count': getattr(config, 'SEHandlerCount', None)
            }

        return load_config
    except Exception as e:
        logging.error(f"Error analyzing load config: {e}")
        return {}

def analyze_relocations(pe) -> List[Dict[str, Any]]:
    """Analyze base relocations with summarized entries."""
    try:
        relocations = []
        if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                entry_types = {}
                offsets = []

                for entry in base_reloc.entries:
                    entry_types[entry.type] = entry_types.get(entry.type, 0) + 1
                    offsets.append(entry.rva - base_reloc.struct.VirtualAddress)

                reloc_info = {
                    'virtual_address': base_reloc.struct.VirtualAddress,
                    'size_of_block': base_reloc.struct.SizeOfBlock,
                    'summary': {
                        'total_entries': len(base_reloc.entries),
                        'types': entry_types,
                        'offset_range': (min(offsets), max(offsets)) if offsets else None
                    }
                }

                relocations.append(reloc_info)

        return relocations
    except Exception as e:
        logging.error(f"Error analyzing relocations: {e}")
        return []

def analyze_overlay(pe, file_path: str) -> Dict[str, Any]:
    """Analyze file overlay (data appended after the PE structure)."""
    try:
        overlay_info = {
            'exists': False,
            'offset': 0,
            'size': 0,
            'entropy': 0.0
        }

        # Use pefile's recommended method for overlay
        end_of_pe = pe.get_overlay_data_start_offset()
        if end_of_pe is None:
            return overlay_info # No overlay

        file_size = os.path.getsize(file_path)

        if file_size > end_of_pe:
            with open(file_path, 'rb') as f:
                f.seek(end_of_pe)
                overlay_data = f.read()

                overlay_info['exists'] = True
                overlay_info['offset'] = end_of_pe
                overlay_info['size'] = len(overlay_data)
                overlay_info['entropy'] = calculate_entropy(list(overlay_data))

        return overlay_info
    except Exception as e:
        logging.error(f"Error analyzing overlay: {e}")
        return {}

def analyze_bound_imports(pe) -> List[Dict[str, Any]]:
    """Analyze bound imports with robust error handling."""
    try:
        bound_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            for bound_imp in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                bound_import = {
                    'name': bound_imp.name.decode() if bound_imp.name else None,
                    'timestamp': bound_imp.struct.TimeDateStamp,
                    'references': []
                }

                # Check if `references` exists
                if hasattr(bound_imp, 'references') and bound_imp.references:
                    for ref in bound_imp.references:
                        reference = {
                            'name': ref.name.decode() if ref.name else None,
                            'timestamp': getattr(ref.struct, 'TimeDateStamp', None)
                        }
                        bound_import['references'].append(reference)
                else:
                    logging.info(f"Bound import {bound_import['name']} has no references.")

                bound_imports.append(bound_import)

        return bound_imports
    except Exception as e:
        logging.error(f"Error analyzing bound imports: {e}")
        return []

def analyze_section_characteristics(pe) -> Dict[str, Dict[str, Any]]:
    """Analyze detailed section characteristics."""
    try:
        characteristics = {}
        for section in pe.sections:
            section_name = section.Name.decode(errors='ignore').strip('\x00')
            flags = section.Characteristics

            # Decode section characteristics flags
            section_flags = {
                'CODE': bool(flags & 0x20),
                'INITIALIZED_DATA': bool(flags & 0x40),
                'UNINITIALIZED_DATA': bool(flags & 0x80),
                'MEM_DISCARDABLE': bool(flags & 0x2000000),
                'MEM_NOT_CACHED': bool(flags & 0x4000000),
                'MEM_NOT_PAGED': bool(flags & 0x8000000),
                'MEM_SHARED': bool(flags & 0x10000000),
                'MEM_EXECUTE': bool(flags & 0x20000000),
                'MEM_READ': bool(flags & 0x40000000),
                'MEM_WRITE': bool(flags & 0x80000000)
            }

            characteristics[section_name] = {
                'flags': section_flags,
                'entropy': calculate_entropy(list(section.get_data())),
                'size_ratio': section.SizeOfRawData / pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER.SizeOfImage else 0,
                'pointer_to_raw_data': section.PointerToRawData,
                'pointer_to_relocations': section.PointerToRelocations,
                'pointer_to_line_numbers': section.PointerToLinenumbers,
                'number_of_relocations': section.NumberOfRelocations,
                'number_of_line_numbers': section.NumberOfLinenumbers,
            }

        return characteristics
    except Exception as e:
        logging.error(f"Error analyzing section characteristics: {e}")
        return {}

def analyze_extended_headers(pe) -> Dict[str, Any]:
    """Analyze extended header information."""
    try:
        headers = {
            'dos_header': {
                'e_magic': pe.DOS_HEADER.e_magic,
                'e_cblp': pe.DOS_HEADER.e_cblp,
                'e_cp': pe.DOS_HEADER.e_cp,
                'e_crlc': pe.DOS_HEADER.e_crlc,
                'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
                'e_minalloc': pe.DOS_HEADER.e_minalloc,
                'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
                'e_ss': pe.DOS_HEADER.e_ss,
                'e_sp': pe.DOS_HEADER.e_sp,
                'e_csum': pe.DOS_HEADER.e_csum,
                'e_ip': pe.DOS_HEADER.e_ip,
                'e_cs': pe.DOS_HEADER.e_cs,
                'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
                'e_ovno': pe.DOS_HEADER.e_ovno,
                'e_oemid': pe.DOS_HEADER.e_oemid,
                'e_oeminfo': pe.DOS_HEADER.e_oeminfo
            },
            'nt_headers': {}
        }

        # Ensure NT_HEADERS exists and contains FileHeader
        if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS is not None:
            nt_headers = pe.NT_HEADERS
            if hasattr(nt_headers, 'FileHeader'):
                headers['nt_headers'] = {
                    'signature': nt_headers.Signature,
                    'machine': nt_headers.FileHeader.Machine,
                    'number_of_sections': nt_headers.FileHeader.NumberOfSections,
                    'time_date_stamp': nt_headers.FileHeader.TimeDateStamp,
                    'characteristics': nt_headers.FileHeader.Characteristics
                }

        return headers
    except Exception as e:
        logging.error(f"Error analyzing extended headers: {e}")
        return {}

def serialize_data(data) -> Any:
    """Serialize data for output, ensuring compatibility."""
    try:
        return list(data) if data else None
    except Exception:
        return None

def analyze_rich_header(pe) -> Dict[str, Any]:
    """Analyze Rich header details."""
    try:
        rich_header = {}
        if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
            rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
            rich_header['values'] = serialize_data(pe.RICH_HEADER.values)
            rich_header['clear_data'] = serialize_data(pe.RICH_HEADER.clear_data)
            rich_header['key'] = serialize_data(pe.RICH_HEADER.key)
            rich_header['raw_data'] = serialize_data(pe.RICH_HEADER.raw_data)

            # Decode CompID and build number information
            compid_info = []
            for i in range(0, len(pe.RICH_HEADER.values), 2):
                if i + 1 < len(pe.RICH_HEADER.values):
                    comp_id = pe.RICH_HEADER.values[i] >> 16
                    build_number = pe.RICH_HEADER.values[i] & 0xFFFF
                    count = pe.RICH_HEADER.values[i + 1]
                    compid_info.append({
                        'comp_id': comp_id,
                        'build_number': build_number,
                        'count': count
                    })
            rich_header['comp_id_info'] = compid_info

        return rich_header
    except Exception as e:
        logging.error(f"Error analyzing Rich header: {e}")
        return {}

def extract_numeric_features(file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """
    Extract numeric features of a file using pefile.
    """
    try:
        # Load the PE file
        pe = pefile.PE(file_path, fast_load=True)

        # Extract features
        numeric_features = {
            # Optional Header Features
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
            'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
            'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
            'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
            'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
            'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
            'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,

            # Section Headers
            'sections': [
                {
                    'name': section.Name.decode(errors='ignore').strip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'virtual_address': section.VirtualAddress,
                    'size_of_raw_data': section.SizeOfRawData,
                    'pointer_to_raw_data': section.PointerToRawData,
                    'characteristics': section.Characteristics,
                }
                for section in pe.sections
            ],

            # Imported Functions
            'imports': [
                imp.name.decode(errors='ignore') if imp.name else "Unknown"
                for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                for imp in getattr(entry, 'imports', [])
            ] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],

            # Exported Functions
            'exports': [
                exp.name.decode(errors='ignore') if exp.name else "Unknown"
                for exp in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
            ] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],

            # Resources
            'resources': [
                {
                    'type_id': getattr(getattr(resource_type, 'struct', None), 'Id', None),
                    'resource_id': getattr(getattr(resource_id, 'struct', None), 'Id', None),
                    'lang_id': getattr(getattr(resource_lang, 'struct', None), 'Id', None),
                    'size': getattr(getattr(resource_lang, 'data', None), 'Size', None),
                    'codepage': getattr(getattr(resource_lang, 'data', None), 'CodePage', None),
                }
                for resource_type in
                (pe.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') else [])
                for resource_id in (resource_type.directory.entries if hasattr(resource_type, 'directory') else [])
                for resource_lang in (resource_id.directory.entries if hasattr(resource_id, 'directory') else [])
                if hasattr(resource_lang, 'data')
            ] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],

            # Certificates
            'certificates': analyze_certificates(pe),  # Analyze certificates

            # DOS Stub Analysis
            'dos_stub': analyze_dos_stub(pe),  # DOS stub analysis here

            # TLS Callbacks
            'tls_callbacks': analyze_tls_callbacks(pe),  # TLS callback analysis here

            # Delay Imports
            'delay_imports': analyze_delay_imports(pe),  # Delay imports analysis here

            # Load Config
            'load_config': analyze_load_config(pe),  # Load config analysis here

            # Relocations
            'relocations': analyze_relocations(pe),  # Relocations analysis here

            # Bound Imports
            'bound_imports': analyze_bound_imports(pe),  # Bound imports analysis here

            # Section Characteristics
            'section_characteristics': analyze_section_characteristics(pe),  # Section characteristics analysis here

            # Extended Headers
            'extended_headers': analyze_extended_headers(pe),  # Extended headers analysis here

            # Rich Header
            'rich_header': analyze_rich_header(pe),  # Rich header analysis here

            # Overlay
            'overlay': analyze_overlay(pe, file_path),  # Overlay analysis here
        }
        pe.close()
        # Add numeric tag if provided
        if rank is not None:
            numeric_features['numeric_tag'] = rank

        return numeric_features

    except pefile.PEFormatError:
        logging.error(f"File is not a valid PE format: {file_path}")
        return None
    except Exception as ex:
        logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
        return None

def calculate_vector_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculates similarity between two numeric vectors using cosine similarity."""
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0

    # Convert to numpy arrays for vector operations
    vec1 = np.array(vec1, dtype=np.float64)
    vec2 = np.array(vec2, dtype=np.float64)

    # Calculate cosine similarity
    dot_product = np.dot(vec1, vec2)
    norm_vec1 = np.linalg.norm(vec1)
    norm_vec2 = np.linalg.norm(vec2)

    if norm_vec1 == 0 or norm_vec2 == 0:
        return 1.0 if norm_vec1 == norm_vec2 else 0.0

    # The result of dot_product / (norm_vec1 * norm_vec2) is between -1 and 1.
    # We scale it to be in the [0, 1] range for easier interpretation.
    cosine_similarity = dot_product / (norm_vec1 * norm_vec2)
    return (cosine_similarity + 1) / 2

# Load ML definitions

def load_ml_definitions(filepath: str) -> bool:
    global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names

    if not os.path.exists(filepath):
        logging.error(f"Machine learning definitions file not found: {filepath}. ML scanning will be disabled.")
        return False

    try:
        with open(filepath, 'r', encoding='utf-8-sig') as results_file:
            ml_defs = json.load(results_file)

        # Malicious section
        malicious_entries = ml_defs.get("malicious", [])
        malicious_numeric_features = []
        malicious_file_names = []
        for entry in malicious_entries:
            numeric = [
                float(entry.get("SizeOfOptionalHeader", 0)),
                float(entry.get("MajorLinkerVersion", 0)),
                float(entry.get("MinorLinkerVersion", 0)),
                float(entry.get("SizeOfCode", 0)),
                float(entry.get("SizeOfInitializedData", 0)),
                float(entry.get("SizeOfUninitializedData", 0)),
                float(entry.get("AddressOfEntryPoint", 0)),
                float(entry.get("ImageBase", 0)),
                float(entry.get("Subsystem", 0)),
                float(entry.get("DllCharacteristics", 0)),
                float(entry.get("SizeOfStackReserve", 0)),
                float(entry.get("SizeOfHeapReserve", 0)),
                float(entry.get("CheckSum", 0)),
                float(entry.get("NumberOfRvaAndSizes", 0)),
                float(entry.get("SizeOfImage", 0)),
                float(len(entry.get("imports", []))),
                float(len(entry.get("exports", []))),
                float(len(entry.get("resources", []))),
                float(int(entry.get("overlay", {}).get("exists", False))),
            ]
            malicious_numeric_features.append(numeric)
            filename = entry.get("file_info", {}).get("filename", "unknown")
            malicious_file_names.append(filename)

        # Benign section
        benign_entries = ml_defs.get("benign", [])
        benign_numeric_features = []
        benign_file_names = []
        for entry in benign_entries:
            numeric = [
                float(entry.get("SizeOfOptionalHeader", 0)),
                float(entry.get("MajorLinkerVersion", 0)),
                float(entry.get("MinorLinkerVersion", 0)),
                float(entry.get("SizeOfCode", 0)),
                float(entry.get("SizeOfInitializedData", 0)),
                float(entry.get("SizeOfUninitializedData", 0)),
                float(entry.get("AddressOfEntryPoint", 0)),
                float(entry.get("ImageBase", 0)),
                float(entry.get("Subsystem", 0)),
                float(entry.get("DllCharacteristics", 0)),
                float(entry.get("SizeOfStackReserve", 0)),
                float(entry.get("SizeOfHeapReserve", 0)),
                float(entry.get("CheckSum", 0)),
                float(entry.get("NumberOfRvaAndSizes", 0)),
                float(entry.get("SizeOfImage", 0)),
                float(len(entry.get("imports", []))),
                float(len(entry.get("exports", []))),
                float(len(entry.get("resources", []))),
                float(int(entry.get("overlay", {}).get("exists", False))),
            ]
            benign_numeric_features.append(numeric)
            filename = entry.get("file_info", {}).get("filename", "unknown")
            benign_file_names.append(filename)

        logging.info(f"[!] Loaded {len(malicious_numeric_features)} malicious and {len(benign_numeric_features)} benign ML definitions.")
        return True

    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Failed to load or parse ML definitions from {filepath}: {e}. ML scanning will be disabled.")
        return False

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning definitions loaded from JSON."""
    malware_definition = "Unknown"
    logging.info(f"Starting machine learning scan for file: {file_path}")

    try:
        pe = pefile.PE(file_path)
        pe.close()
    except pefile.PEFormatError:
        logging.error(f"File {file_path} is not a valid PE file. Returning default value 'Unknown'.")
        return False, malware_definition, 0

    logging.info(f"File {file_path} is a valid PE file, proceeding with feature extraction.")

    file_numeric_features = extract_numeric_features(file_path)
    if not file_numeric_features:
        return False, "Feature-Extraction-Failed", 0

    is_malicious_ml = False
    nearest_malicious_similarity = 0
    nearest_benign_similarity = 0

    # Check malicious definitions
    for ml_feats, info in zip(malicious_numeric_features, malicious_file_names):
        similarity = calculate_vector_similarity(file_numeric_features, ml_feats)
        nearest_malicious_similarity = max(nearest_malicious_similarity, similarity)

        if similarity >= threshold:
            is_malicious_ml = True

            # Handle both string and dict cases
            if isinstance(info, dict):
                malware_definition = info.get('file_name', 'Unknown')
                rank = info.get('numeric_tag', 'N/A')
            elif isinstance(info, str):
                malware_definition = info
                rank = 'N/A'
            else:
                malware_definition = str(info)
                rank = 'N/A'

            logging.critical(f"Malicious activity detected in {file_path}. Definition: {malware_definition}, similarity: {similarity}, rank: {rank}")

    # If not malicious, check benign
    if not is_malicious_ml:
        for ml_feats, info in zip(benign_numeric_features, benign_file_names):
            similarity = calculate_vector_similarity(file_numeric_features, ml_feats)
            nearest_benign_similarity = max(nearest_benign_similarity, similarity)

            # Handle both string and dict cases
            if isinstance(info, dict):
                benign_definition = info.get('file_name', 'Unknown')
            elif isinstance(info, str):
                benign_definition = info
            else:
                benign_definition = str(info)

        if nearest_benign_similarity >= 0.93:
            malware_definition = "Benign"
            logging.info(f"File {file_path} is classified as benign ({benign_definition}) with similarity: {nearest_benign_similarity}")
        else:
            malware_definition = "Unknown"
            logging.info(f"File {file_path} is classified as unknown with similarity: {nearest_benign_similarity}")

    # Return result
    if is_malicious_ml:
        return True, malware_definition, nearest_malicious_similarity
    else:
        return False, malware_definition, nearest_benign_similarity

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

# Add these helper functions near the top after imports
def get_code_version_hash():
    """Generate a hash of critical ML functions to detect code changes."""
    try:
        critical_functions = [
            inspect.getsource(calculate_vector_similarity),
            inspect.getsource(scan_file_with_machine_learning_ai),
            inspect.getsource(load_ml_definitions)
        ]
        code_content = ''.join(critical_functions)
        return hashlib.md5(code_content.encode()).hexdigest()[:8]
    except Exception:
        return "unknown"

# Replace your existing load_scan_cache function
def load_scan_cache(filepath: str) -> Dict[str, Any]:
    with perf_monitor.timer("cache_load"):
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                # Check if this cache was created with the same code version
                current_code_hash = get_code_version_hash()
                cache_code_hash = cache_data.get('_code_version', '')
                
                if cache_code_hash != current_code_hash:
                    logging.warning(f"Code version changed (was {cache_code_hash}, now {current_code_hash}). Invalidating cache.")
                    return {'_code_version': current_code_hash}
                
                return cache_data
            except Exception as e:
                logging.warning(f"Could not read cache file: {e}")
        
        return {'_code_version': get_code_version_hash()}

# Replace your existing save_scan_cache function
def save_scan_cache(filepath: str, cache: Dict[str, Any]):
    with perf_monitor.timer("cache_save"):
        try:
            # Ensure code version is always saved
            cache['_code_version'] = get_code_version_hash()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(cache, f, indent=4)
        except Exception as e:
            logging.error(f"Could not save cache file: {e}")

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

    # load cache (now with auto-invalidation)
    t0 = time.perf_counter()
    cache = load_scan_cache(SCAN_CACHE_FILE)
    timings['cache_load'] = time.perf_counter() - t0

    # Skip cache lookups that might contain old buggy results
    # The new load_scan_cache will return empty cache if code changed

    # md5
    t0 = time.perf_counter()
    md5_hash = calculate_md5(file_to_scan)
    timings['md5_calculation'] = time.perf_counter() - t0
    if not md5_hash:
        return

    # Check MD5 cache only if it's not a system key
    if md5_hash in cache and not md5_hash.startswith('_'):
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
        logging.info("Cache cleared manually.")

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
