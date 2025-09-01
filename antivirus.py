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
import json
import hashlib
import string
import threading
import queue
from logging.handlers import QueueHandler
from typing import List, Dict, Any, Optional, Set, Tuple
from collections import Counter
import shutil
import inspect
import copy
import numpy as np
import capstone
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager, Lock

# ---------------- Optional third-party flags ----------------
_have_yara = False
_have_yara_x = False
_have_chardet = False
_have_pefile = False

try:
    import yara
    _have_yara = True
except ImportError:
    pass # Warnings will be handled in worker init

try:
    import yara_x
    _have_yara_x = True
except ImportError:
    pass

try:
    import pefile
    _have_pefile = True
except ImportError:
    pass

try:
    import chardet
    _have_chardet = True
except ImportError:
    pass

from tqdm import tqdm

# ---------------- Paths & configuration ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = 'antivirus.log'
YARA_RULES_DIR = os.path.join(BASE_DIR, 'yara')
EXCLUDED_RULES_FILE = os.path.join(BASE_DIR, 'excluded', 'excluded_rules.txt')
ML_RESULTS_JSON = os.path.join(BASE_DIR, 'machine_learning', 'results.json')
SCAN_CACHE_FILE = os.path.join(BASE_DIR, 'scan_cache.json')

# Limits / concurrency
INPROC_SEMAPHORE = threading.Semaphore(max(1, min(8, (os.cpu_count() or 1))))

# YARA order
ORDERED_YARA_FILES = [
    'yaraxtr.yrc',
    'valhalla-rules.yrc',
    'icewater.yrc',
    'machine_learning.yrc',
    'clean_rules.yrc'
]

# ---------------- Globals (for main process and worker processes) ----------------
# These will be populated in each worker by the initializer
_global_yara_compiled: Dict[str, Any] = {}
malicious_numeric_features: List[List[float]] = []
malicious_file_names: List[str] = []
benign_numeric_features: List[List[float]] = []
benign_file_names: List[str] = []
CLAMAV_INPROC = None
CLAMAV_MODULE = None
_worker_excluded_rules: Set[str] = set()

# In-memory caches (local to each process)
_memory_cache_clamav: Dict[str, Dict[str, Any]] = {}
_memory_cache_yara: Dict[str, List[Dict]] = {}
_memory_cache_ml: Dict[str, Tuple[bool, str, float]] = {}
_clamav_db_version = None

# Thread-safe lock for operations within a single process if needed
global_lock = threading.Lock()

# ---------------- Multiprocessing Worker Initializer and Logger ----------------
def log_listener(log_q: queue.Queue):
    """
    Listens for log records on a queue and handles them.
    This runs in a separate thread in the main process.
    """
    while True:
        try:
            record = log_q.get()
            if record is None:  # Sentinel value to stop
                break
            logger = logging.getLogger(record.name)
            logger.handle(record)
        except Exception:
            import traceback
            print("Error in log listener:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

def worker_init(log_q: queue.Queue, excluded_rules: Set[str], ml_defs_path: str, yara_rules_path: str):
    """
    Initializer for each worker process in the pool.
    - Configures logging to send records to the main process via a queue.
    - Initializes ClamAV, YARA, and ML models once per process for efficiency.
    """
    # 1. Configure logging for this worker to send to the main process
    h = QueueHandler(log_q)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(h)
    root.setLevel(logging.INFO)

    # 2. Set up globals for this worker process
    global _worker_excluded_rules, _global_yara_compiled, CLAMAV_INPROC, CLAMAV_MODULE
    global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names
    
    _worker_excluded_rules = excluded_rules

    # 3. Initialize services
    logging.info(f"Initializing worker PID: {os.getpid()}")
    
    # Init ClamAV
    db_abs = os.path.abspath(os.path.join(BASE_DIR, "clamav", "database"))
    init_inproc_clamav(dbpath=db_abs, autoreload=False)
    
    # Load YARA rules
    preload_yara_rules(yara_rules_path)
    
    # Load ML definitions
    load_ml_definitions(ml_defs_path)

# ---------------- Utility functions ----------------
def setup_directories():
    for d in (YARA_RULES_DIR, os.path.dirname(EXCLUDED_RULES_FILE), os.path.dirname(ML_RESULTS_JSON)):
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

def calculate_md5(file_path: str) -> str:
    h = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logging.error(f"MD5 failed for {file_path}: {e}")
        return ""

# ---------------- ClamAV database version detection ----------------
def get_clamav_db_version() -> str:
    """Get ClamAV database version/timestamp for cache invalidation."""
    try:
        db_path = os.path.join(BASE_DIR, "clamav", "database")
        if not os.path.exists(db_path):
            return "no_db"
        
        db_files = [f"{file}:{os.path.getmtime(os.path.join(db_path, file))}" 
                    for file in os.listdir(db_path) 
                    if file.endswith(('.cvd', '.cld', '.hdb', '.ndb', '.pdb'))]
        
        if not db_files:
            return "empty_db"
            
        db_signature = ':'.join(sorted(db_files))
        return hashlib.md5(db_signature.encode()).hexdigest()[:12]
    except Exception as e:
        logging.warning(f"Could not determine ClamAV DB version: {e}")
        return "unknown"

# ---------------- YARA preload ----------------
def preload_yara_rules(rules_dir: str):
    global _global_yara_compiled
    for rule_filename in ORDERED_YARA_FILES:
        rule_filepath = os.path.join(rules_dir, rule_filename)
        if not os.path.exists(rule_filepath):
            continue
        try:
            if rule_filename == 'yaraxtr.yrc' and _have_yara_x:
                with open(rule_filepath, "rb") as f:
                    _global_yara_compiled[rule_filename] = yara_x.Rules.deserialize_from(f)
            elif _have_yara:
                _global_yara_compiled[rule_filename] = yara.load(rule_filepath)
            else:
                logging.warning(f"yara-python not available; cannot load {rule_filename}")
                continue
            logging.info(f"Worker {os.getpid()} preloaded YARA rules: {rule_filename}")
        except Exception as e:
            logging.error(f"Failed to preload YARA rule {rule_filename} in worker {os.getpid()}: {e}")

# ---------------- In-process ClamAV init (STRICT) ----------------
def init_inproc_clamav(dbpath: Optional[str] = None, autoreload: bool = True) -> None:
    global CLAMAV_INPROC, CLAMAV_MODULE

    clamav_py_path = os.path.join(BASE_DIR, "clamav.py")
    if not os.path.exists(clamav_py_path):
        logging.critical(f"clamav.py not found: {clamav_py_path}")
        sys.exit(2)

    clamav_assets_dir = os.path.join(BASE_DIR, "clamav")
    libclamav_dll = os.path.join(clamav_assets_dir, "libclamav.dll")
    if not os.path.exists(libclamav_dll):
        logging.critical(f"libclamav.dll not found: {libclamav_dll}")
        sys.exit(2)

    try:
        import clamav as _clamav_pkg
        CLAMAV_MODULE = _clamav_pkg
    except Exception as e:
        logging.critical(f"Cannot import clamav.py: {e}")
        sys.exit(2)

    Scanner = getattr(CLAMAV_MODULE, "Scanner", None)
    if Scanner is None:
        logging.critical("ClamAV module does not expose Scanner class")
        sys.exit(3)

    dbpath = dbpath or os.path.join(clamav_assets_dir, "database")

    try:
        CLAMAV_INPROC = Scanner(libclamav_dll, dbpath=dbpath, autoreload=autoreload)
        if not CLAMAV_INPROC or not getattr(CLAMAV_INPROC, "engine", None):
            raise RuntimeError("Failed to initialize ClamAV engine")
        logging.info(f"Successfully initialized in-process ClamAV Scanner in worker {os.getpid()}.")
    except Exception as e:
        logging.critical(f"Failed to instantiate Scanner in worker {os.getpid()}: {e}")
        sys.exit(4)

# ---------------- Scan Wrappers ----------------
def scan_file_with_clamav(path: str) -> Dict[str, Any]:
    if CLAMAV_INPROC is None or CLAMAV_MODULE is None:
        return {'status': 'error', 'details': 'ClamAV not initialized in this process.'}

    try:
        ret, virus_name = CLAMAV_INPROC.scanFile(path)
        if ret == CLAMAV_MODULE.CL_CLEAN:
            return {'status': 'clean', 'details': 'No threat found.'}
        elif ret == CLAMAV_MODULE.CL_VIRUS:
            return {'status': 'threat_found', 'details': virus_name or 'Unknown'}
        else:
            err_msg = CLAMAV_INPROC.get_error_message(ret)
            return {'status': 'error', 'details': err_msg}
    except Exception as e:
        logging.exception(f"ClamAV scan via wrapper failed for {path}")
        return {'status': 'error', 'details': str(e)}

# ... (The rest of the file remains largely the same, but with `excluded_rules` removed from YARA function signatures)

# ---------------- Enhanced scan functions with memory caching ----------------
def scan_file_with_clamav_hybrid(path: str) -> Dict[str, Any]:
    """ClamAV scan with in-memory cache + database update detection."""
    global _memory_cache_clamav
    
    md5_hash = calculate_md5(path)
    if not md5_hash:
        return {'status': 'error', 'details': 'Could not calculate MD5'}
    
    if check_clamav_db_updated():
        logging.info("ClamAV database updated - clearing in-memory ClamAV cache")
        _memory_cache_clamav.clear()
    
    if md5_hash in _memory_cache_clamav:
        return _memory_cache_clamav[md5_hash]
    
    result = scan_file_with_clamav(path)
    _memory_cache_clamav[md5_hash] = result
    return result

def scan_file_with_yara_hybrid(file_path: str) -> List[Dict]:
    """YARA scan with in-memory cache. Uses worker-global excluded rules."""
    global _memory_cache_yara
    
    md5_hash = calculate_md5(file_path)
    if not md5_hash:
        return []
    
    if md5_hash in _memory_cache_yara:
        return _memory_cache_yara[md5_hash]
    
    result = scan_file_with_yara_sequentially(file_path)
    _memory_cache_yara[md5_hash] = result
    return result

def scan_file_with_ml_hybrid(file_path: str, threshold: float = 0.86) -> Tuple[bool, str, float]:
    """ML scan with in-memory cache."""
    global _memory_cache_ml
    
    md5_hash = calculate_md5(file_path)
    if not md5_hash:
        return False, "MD5-Failed", 0.0
    
    if md5_hash in _memory_cache_ml:
        return _memory_cache_ml[md5_hash]
    
    result = scan_file_with_machine_learning_ai(file_path, threshold)
    _memory_cache_ml[md5_hash] = result
    return result

def check_clamav_db_updated() -> bool:
    """Check if ClamAV database has been updated since last check."""
    global _clamav_db_version
    current_version = get_clamav_db_version()
    
    if _clamav_db_version is None:
        _clamav_db_version = current_version
        return False
    
    if _clamav_db_version != current_version:
        _clamav_db_version = current_version
        return True
    
    return False

# ---------------- DIE heuristics & YARA scanning ----------------
def is_plain_text(data: bytes, null_byte_threshold: float = 0.01, printable_threshold: float = 0.95) -> bool:
    if not data: return True
    if data.count(0) / len(data) > null_byte_threshold: return False
    if sum(b in set(bytes(string.printable, 'ascii')) for b in data) / len(data) < printable_threshold: return False
    enc = 'utf-8'
    if _have_chardet:
        try: enc = chardet.detect(data).get('encoding') or 'utf-8'
        except Exception: pass
    try:
        data.decode(enc)
        return True
    except Exception:
        return False

def check_file_type_with_die(file_path: str) -> str:
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(4096)
        return "Binary\nFormat: plain text" if is_plain_text(sample) else "Unknown"
    except Exception as e:
        return f"Error: {e}"

def load_excluded_rules(filepath: str) -> Set[str]:
    if not os.path.exists(filepath): return set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        print(f"Error reading excluded rules file: {e}", file=sys.stderr)
        return set()

def extract_yarax_match_details(rule, source):
    return {"rule": rule.identifier, "tags": getattr(rule, 'tags', []), "meta": {"source": source}}

def scan_file_with_yara_sequentially(file_path: str) -> List[Dict]:
    """Sequential YARA scanning using worker-global compiled rules and exclusions."""
    global _worker_excluded_rules
    data_content = None

    for rule_filename in ORDERED_YARA_FILES:
        if rule_filename not in _global_yara_compiled:
            continue
        
        compiled = _global_yara_compiled[rule_filename]
        try:
            if rule_filename == "yaraxtr.yrc" and _have_yara_x:
                if data_content is None:
                    with open(file_path, "rb") as f: data_content = f.read()
                    if not data_content: continue
                
                scanner = yara_x.Scanner(rules=compiled)
                scan_results = scanner.scan(data_content)
                matches = [extract_yarax_match_details(rule, rule_filename) 
                           for rule in getattr(scan_results, "matching_rules", []) 
                           if rule.identifier not in _worker_excluded_rules]
                if matches: return matches
            elif _have_yara:
                matches = compiled.match(filepath=file_path)
                filtered = [{"rule": m.rule, "tags": m.tags, "meta": m.meta}
                            for m in matches if m.rule not in _worker_excluded_rules]
                if filtered: return filtered
        except Exception as e:
            logging.error(f"Error during YARA scan with {rule_filename} on {file_path}: {e}")
            continue
    return []

# --- PE Analysis and Feature Extraction Functions ---
# NOTE: The entire PEFeatureExtractor class and related ML functions
# (calculate_vector_similarity, scan_file_with_machine_learning_ai, load_ml_definitions)
# are included here but omitted for brevity in this diff view. Their internal logic is unchanged.
class PEFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        # Use a more efficient way to get byte counts
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        total_bytes = len(data)

        # Filter out zero counts to avoid log(0)
        probs = counts[counts > 0] / total_bytes
        entropy = -np.sum(probs * np.log2(probs))

        return float(entropy)

    def disassemble_all_sections(self, pe) -> Dict[str, Any]:
        """
        Disassembles all sections of the PE file using Capstone and returns
        instruction counts and a packing heuristic for each section and the file overall.
        """
        analysis = {
            'overall_analysis': {
                'total_instructions': 0,
                'add_count': 0,
                'mov_count': 0,
                'is_likely_packed': None
            },
            'sections': {},
            'error': None
        }

        try:
            # Determine architecture for Capstone
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                analysis['error'] = "Unsupported architecture."
                return analysis

            total_add_count = 0
            total_mov_count = 0
            grand_total_instructions = 0

            # Disassemble each section individually
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                code = section.get_data()
                base_address = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                instruction_counts = {}
                total_instructions_in_section = 0

                if not code:
                    analysis['sections'][section_name] = {
                        'instruction_counts': {},
                        'total_instructions': 0,
                        'add_count': 0,
                        'mov_count': 0,
                        'is_likely_packed': False
                    }
                    continue

                instructions = md.disasm(code, base_address)

                for i in instructions:
                    mnemonic = i.mnemonic
                    instruction_counts[mnemonic] = instruction_counts.get(mnemonic, 0) + 1
                    total_instructions_in_section += 1

                add_count = instruction_counts.get('add', 0)
                mov_count = instruction_counts.get('mov', 0)

                # Aggregate counts for overall file analysis
                total_add_count += add_count
                total_mov_count += mov_count
                grand_total_instructions += total_instructions_in_section

                # Per-section packing analysis
                analysis['sections'][section_name] = {
                    'instruction_counts': instruction_counts,
                    'total_instructions': total_instructions_in_section,
                    'add_count': add_count,
                    'mov_count': mov_count,
                    'is_likely_packed': add_count > mov_count if total_instructions_in_section > 0 else False
                }

            # Populate the overall, file-wide analysis
            analysis['overall_analysis']['total_instructions'] = grand_total_instructions
            analysis['overall_analysis']['add_count'] = total_add_count
            analysis['overall_analysis']['mov_count'] = total_mov_count
            analysis['overall_analysis']['is_likely_packed'] = total_add_count > total_mov_count if grand_total_instructions > 0 else False

        except Exception as e:
            logging.error(f"Capstone disassembly failed: {e}")
            analysis['error'] = str(e)

        return analysis

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extract comprehensive section data including entropy."""
        raw_data = section.get_data()
        return {
            'name': section.Name.decode(errors='ignore').strip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'virtual_address': section.VirtualAddress,
            'raw_size': section.SizeOfRawData,
            'pointer_to_raw_data': section.PointerToRawData,
            'characteristics': section.Characteristics,
            'entropy': self._calculate_entropy(raw_data),
            'raw_data_size': len(raw_data) if raw_data else 0
        }

    def extract_imports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed import information."""
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_imports = {
                    'dll_name': entry.dll.decode() if entry.dll else None,
                    'imports': [{
                        'name': imp.name.decode() if imp.name else None,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    } for imp in entry.imports]
                }
                imports.append(dll_imports)
        return imports

    def extract_exports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed export information."""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'name': exp.name.decode() if exp.name else None,
                    'address': exp.address,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode() if exp.forwarder else None
                }
                exports.append(export_info)
        return exports

    def _get_callback_addresses(self, pe, address_of_callbacks) -> List[int]:
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

    def analyze_tls_callbacks(self, pe) -> Dict[str, Any]:
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
                    callback_array = self._get_callback_addresses(pe, tls.AddressOfCallBacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array

            return tls_callbacks
        except Exception as e:
            logging.error(f"Error analyzing TLS callbacks: {e}")
            return {}

    def analyze_dos_stub(self, pe) -> Dict[str, Any]:
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
                        dos_stub['entropy'] = self._calculate_entropy(dos_stub_data)

            return dos_stub
        except Exception as e:
            logging.error(f"Error analyzing DOS stub: {e}")
            return {}

    def analyze_certificates(self, pe) -> Dict[str, Any]:
        """Analyze security certificates."""
        try:
            cert_info = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
                cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size

                # Extract certificate attributes if available
                if hasattr(pe, 'VS_FIXEDFILEINFO'):
                    cert_info['fixed_file_info'] = {
                        'signature': pe.VS_FIXEDFILEINFO.Signature,
                        'struct_version': pe.VS_FIXEDFILEINFO.StrucVersion,
                        'file_version': f"{pe.VS_FIXEDFILEINFO.FileVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.FileVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionLS & 0xFFFF}",
                        'product_version': f"{pe.VS_FIXEDFILEINFO.ProductVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.ProductVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionLS & 0xFFFF}",
                        'file_flags': pe.VS_FIXEDFILEINFO.FileFlags,
                        'file_os': pe.VS_FIXEDFILEINFO.FileOS,
                        'file_type': pe.VS_FIXEDFILEINFO.FileType,
                        'file_subtype': pe.VS_FIXEDFILEINFO.FileSubtype,
                    }

            return cert_info
        except Exception as e:
            logging.error(f"Error analyzing certificates: {e}")
            return {}

    def analyze_delay_imports(self, pe) -> List[Dict[str, Any]]:
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
                        'attributes': getattr(entry.struct, 'Attributes', None),  # Use getattr for safe access
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

    def analyze_load_config(self, pe) -> Dict[str, Any]:
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
                    'security_cookie': config.SecurityCookie,
                    'se_handler_table': config.SEHandlerTable,
                    'se_handler_count': config.SEHandlerCount
                }

            return load_config
        except Exception as e:
            logging.error(f"Error analyzing load config: {e}")
            return {}

    def analyze_relocations(self, pe) -> List[Dict[str, Any]]:
        """Analyze base relocations with summarized entries."""
        try:
            relocations = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                    # Summarize relocation entries
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
                            'types': entry_types,  # Counts of each relocation type
                            'offset_range': (min(offsets), max(offsets)) if offsets else None
                        }
                    }

                    relocations.append(reloc_info)

            return relocations
        except Exception as e:
            logging.error(f"Error analyzing relocations: {e}")
            return []

    def analyze_bound_imports(self, pe) -> List[Dict[str, Any]]:
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
                        logging.warning(f"Bound import {bound_import['name']} has no references.")

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logging.error(f"Error analyzing bound imports: {e}")
            return []

    def analyze_section_characteristics(self, pe) -> Dict[str, Dict[str, Any]]:
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
                    'entropy': self._calculate_entropy(section.get_data()),
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

    def analyze_extended_headers(self, pe) -> Dict[str, Any]:
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

    def serialize_data(self, data) -> Any:
        """Serialize data for output, ensuring compatibility."""
        try:
            return list(data) if data else None
        except Exception:
            return None

    def analyze_rich_header(self, pe) -> Dict[str, Any]:
        """Analyze Rich header details."""
        try:
            rich_header = {}
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
                rich_header['values'] = self.serialize_data(pe.RICH_HEADER.values)
                rich_header['clear_data'] = self.serialize_data(pe.RICH_HEADER.clear_data)
                rich_header['key'] = self.serialize_data(pe.RICH_HEADER.key)
                rich_header['raw_data'] = self.serialize_data(pe.RICH_HEADER.raw_data)

                # Decode CompID and build number information
                compid_info = []
                if rich_header['values']:
                    for i in range(0, len(rich_header['values']), 2):
                        if i + 1 < len(rich_header['values']):
                            comp_id = rich_header['values'][i] >> 16
                            build_number = rich_header['values'][i] & 0xFFFF
                            count = rich_header['values'][i + 1]
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

    def analyze_overlay(self, pe, file_path: str) -> Dict[str, Any]:
        """Analyze file overlay (data appended after the PE structure)."""
        try:
            overlay_info = {
                'exists': False,
                'offset': 0,
                'size': 0,
                'entropy': 0.0
            }

            # Calculate the end of the PE structure
            if not pe.sections:
                 return overlay_info

            last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_pe = last_section.PointerToRawData + last_section.SizeOfRawData

            # Get file size
            file_size = os.path.getsize(file_path)

            # Check for overlay
            if file_size > end_of_pe:
                with open(file_path, 'rb') as f:
                    f.seek(end_of_pe)
                    overlay_data = f.read()

                    overlay_info['exists'] = True
                    overlay_info['offset'] = end_of_pe
                    overlay_info['size'] = len(overlay_data)
                    overlay_info['entropy'] = self._calculate_entropy(overlay_data)

            return overlay_info
        except Exception as e:
            logging.error(f"Error analyzing overlay: {e}")
            return {}

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extract numeric features of a file using pefile.
        Ensures pefile.PE is closed even on exceptions to avoid leaking file handles on Windows.
        """
        pe = None
        try:

            try:
                # Attempt to load PE file directly
                pe = pefile.PE(file_path, fast_load=True)
            except pefile.PEFormatError:
                return None
            except Exception as ex:
                logging.error(f"Error loading {file_path} as PE: {str(ex)}", exc_info=True)
                return None
            try:
                pe.parse_data_directories()
            except Exception:
                logging.debug(f"pe.parse_data_directories() failed for {file_path}", exc_info=True)

            # Extract features
            numeric_features = {
                # Capstone analysis for packing
                'section_disassembly': self.disassemble_all_sections(pe),

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

                # Debug Information
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else [],

                # Certificates
                'certificates': self.analyze_certificates(pe),  # Analyze certificates

                # DOS Stub Analysis
                'dos_stub': self.analyze_dos_stub(pe),  # DOS stub analysis here

                # TLS Callbacks
                'tls_callbacks': self.analyze_tls_callbacks(pe),  # TLS callback analysis here

                # Delay Imports
                'delay_imports': self.analyze_delay_imports(pe),  # Delay imports analysis here

                # Load Config
                'load_config': self.analyze_load_config(pe),  # Load config analysis here

                # Bound Imports
                'bound_imports': self.analyze_bound_imports(pe),  # Bound imports analysis here

                # Section Characteristics
                'section_characteristics': self.analyze_section_characteristics(pe),
                # Section characteristics analysis here

                # Extended Headers
                'extended_headers': self.analyze_extended_headers(pe),  # Extended headers analysis here

                # Rich Header
                'rich_header': self.analyze_rich_header(pe),  # Rich header analysis here

                # Overlay
                'overlay': self.analyze_overlay(pe, file_path),  # Overlay analysis here

                #Relocations
                'relocations': self.analyze_relocations(pe) #Relocations analysis here
            }

            # Add numeric tag if provided
            if rank is not None:
                numeric_features['numeric_tag'] = rank

            return numeric_features

        except Exception as ex:
            logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None
        finally:
            # ensure PE handle is closed to release underlying file descriptor
            try:
                if pe is not None:
                    pe.close()
            except Exception:
                logging.debug(f"Failed to close pe for {file_path}", exc_info=True)

pe_extractor = PEFeatureExtractor()

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

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning definitions loaded from JSON."""
    malware_definition = "Unknown"
    try:
        pe = pefile.PE(file_path)
        pe.close()
    except pefile.PEFormatError:
        return False, malware_definition, 0

    file_numeric_features = pe_extractor.extract_numeric_features(file_path)
    if not file_numeric_features:
        return False, "Feature-Extraction-Failed", 0

    is_malicious_ml = False
    nearest_malicious_similarity = 0
    nearest_benign_similarity = 0

    # Check malicious definitions
    for ml_feats, info in zip(malicious_numeric_features, malicious_file_names):
        similarity = calculate_vector_similarity(list(file_numeric_features.values()), ml_feats)
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
            similarity = calculate_vector_similarity(list(file_numeric_features.values()), ml_feats)
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

# Load ML definitions

def load_ml_definitions(filepath: str) -> bool:
    """
    Load ML definitions from a JSON file and populate global numeric feature lists.
    This version understands the extended feature set produced by PEFeatureExtractor
    (section_disassembly, section_characteristics, overlay size, relocations, TLS callbacks, etc.)
    and is defensive about missing or unexpected types.
    """
    global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names

    def to_float(x, default=0.0):
        try:
            if x is None:
                return float(default)
            return float(x)
        except (ValueError, TypeError):
            return float(default)

    def safe_len(x):
        try:
            return len(x) if x is not None else 0
        except Exception:
            return 0

    def section_entropy_stats(section_characteristics):
        # section_characteristics may be a dict keyed by section name with 'entropy' values
        entropies = []
        try:
            if isinstance(section_characteristics, dict):
                for v in section_characteristics.values():
                    e = v.get('entropy') if isinstance(v, dict) else None
                    if e is not None:
                        try:
                            entropies.append(float(e))
                        except (ValueError, TypeError):
                            continue
        except Exception:
            pass
        if not entropies:
            return 0.0, 0.0, 0.0  # mean, min, max
        mean = sum(entropies) / len(entropies)
        return float(mean), float(min(entropies)), float(max(entropies))

    def reloc_summary(relocs):
        # relocs is expected to be a list of relocation blocks with 'summary':{'total_entries':N}
        try:
            total = 0
            blocks = 0
            if isinstance(relocs, list):
                for r in relocs:
                    blocks += 1
                    try:
                        total += int(r.get('summary', {}).get('total_entries', 0))
                    except (ValueError, TypeError):
                        continue
            return total, blocks
        except Exception:
            return 0, 0

    def entry_to_numeric(entry: dict) -> Tuple[List[float], str]:
        if not isinstance(entry, dict):
            entry = {}

        # Core header values (kept from your original vector)
        size_of_optional_header = to_float(entry.get("SizeOfOptionalHeader", 0))
        major_linker = to_float(entry.get("MajorLinkerVersion", 0))
        minor_linker = to_float(entry.get("MinorLinkerVersion", 0))
        size_of_code = to_float(entry.get("SizeOfCode", 0))
        size_of_init_data = to_float(entry.get("SizeOfInitializedData", 0))
        size_of_uninit_data = to_float(entry.get("SizeOfUninitializedData", 0))
        address_of_entry = to_float(entry.get("AddressOfEntryPoint", 0))
        image_base = to_float(entry.get("ImageBase", 0))
        subsystem = to_float(entry.get("Subsystem", 0))
        dll_characteristics = to_float(entry.get("DllCharacteristics", 0))
        size_of_stack_reserve = to_float(entry.get("SizeOfStackReserve", 0))
        size_of_heap_reserve = to_float(entry.get("SizeOfHeapReserve", 0))
        checksum = to_float(entry.get("CheckSum", 0))
        num_rva_and_sizes = to_float(entry.get("NumberOfRvaAndSizes", 0))
        size_of_image = to_float(entry.get("SizeOfImage", 0))

        # Counts
        imports_count = safe_len(entry.get("imports", []))
        exports_count = safe_len(entry.get("exports", []))
        resources_count = safe_len(entry.get("resources", []))
        sections_count = safe_len(entry.get("sections", []))

        # Overlay info
        overlay = entry.get("overlay", {}) or {}
        overlay_exists = int(bool(overlay.get("exists")))
        overlay_size = to_float(overlay.get("size", 0))

        # Section characteristics entropy stats (mean, min, max)
        sec_char = entry.get("section_characteristics", {}) or {}
        sec_entropy_mean, sec_entropy_min, sec_entropy_max = section_entropy_stats(sec_char)

        # Capstone disassembly overall numbers (if available)
        sec_disasm = entry.get("section_disassembly", {}) or {}
        overall = sec_disasm.get("overall_analysis", {}) or {}
        total_instructions = to_float(overall.get("total_instructions", 0))
        total_adds = to_float(overall.get("add_count", 0))
        total_movs = to_float(overall.get("mov_count", 0))
        is_likely_packed = int(bool(overall.get("is_likely_packed")))

        # Derived ratios (guard divide-by-zero)
        add_mov_ratio = (total_adds / (total_movs + 1.0)) if (total_movs is not None) else 0.0
        instrs_per_kb = 0.0
        try:
            instrs_per_kb = total_instructions / ((size_of_image / 1024.0) + 1e-6)
        except Exception:
            instrs_per_kb = 0.0

        # TLS callbacks
        tls = entry.get("tls_callbacks", {}) or {}
        tls_callbacks_list = tls.get("callbacks", []) if isinstance(tls, dict) else []
        num_tls_callbacks = safe_len(tls_callbacks_list)

        # Delay imports
        delay_imports_list = entry.get("delay_imports", []) or []
        num_delay_imports = safe_len(delay_imports_list)

        # Relocations
        relocs = entry.get("relocations", []) or []
        num_reloc_entries, num_reloc_blocks = reloc_summary(relocs)

        # Bound imports
        bound_imports = entry.get("bound_imports", []) or []
        num_bound_imports = safe_len(bound_imports)

        # Debug / certs
        debug_entries = entry.get("debug", []) or []
        num_debug_entries = safe_len(debug_entries)
        cert_info = entry.get("certificates", {}) or {}
        cert_size = to_float(cert_info.get("size", 0))

        # Rich header info (presence)
        rich_header = entry.get("rich_header", {}) or {}
        has_rich = int(bool(rich_header))

        # Build the numeric vector (order matters - keep consistent)
        numeric = [
            # original fields (keep these in same order for backwards compatibility)
            size_of_optional_header,
            major_linker,
            minor_linker,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            address_of_entry,
            image_base,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_heap_reserve,
            checksum,
            num_rva_and_sizes,
            size_of_image,

            # counts (originally present)
            float(imports_count),
            float(exports_count),
            float(resources_count),
            float(overlay_exists),

            # new / extended features
            float(sections_count),
            float(sec_entropy_mean),
            float(sec_entropy_min),
            float(sec_entropy_max),
            float(total_instructions),
            float(total_adds),
            float(total_movs),
            float(is_likely_packed),
            float(add_mov_ratio),
            float(instrs_per_kb),

            float(overlay_size),
            float(num_tls_callbacks),
            float(num_delay_imports),
            float(num_reloc_entries),
            float(num_reloc_blocks),
            float(num_bound_imports),
            float(num_debug_entries),
            float(cert_size),
            float(has_rich)
        ]

        filename = (entry.get("file_info", {}) or {}).get("filename", "unknown")
        return numeric, filename

    # --- main loader body ---
    if not os.path.exists(filepath):
        logging.error(f"Machine learning definitions file not found: {filepath}. ML scanning will be disabled.")
        return False

    try:
        with open(filepath, 'r', encoding='utf-8-sig') as results_file:
            ml_defs = json.load(results_file)

        # Malicious section
        malicious_entries = ml_defs.get("malicious", []) or []
        malicious_numeric_features_local = []
        malicious_file_names_local = []
        for entry in malicious_entries:
            numeric, filename = entry_to_numeric(entry)
            malicious_numeric_features_local.append(numeric)
            malicious_file_names_local.append(filename)

        # Benign section
        benign_entries = ml_defs.get("benign", []) or []
        benign_numeric_features_local = []
        benign_file_names_local = []
        for entry in benign_entries:
            numeric, filename = entry_to_numeric(entry)
            benign_numeric_features_local.append(numeric)
            benign_file_names_local.append(filename)

        # Safely update globals
        global malicious_numeric_features, malicious_file_names, benign_numeric_features, benign_file_names
        malicious_numeric_features = malicious_numeric_features_local
        malicious_file_names = malicious_file_names_local
        benign_numeric_features = benign_numeric_features_local
        benign_file_names = benign_file_names_local

        logging.info(f"[!] Loaded {len(malicious_numeric_features)} malicious and {len(benign_numeric_features)} benign ML definitions (vectors length = {len(malicious_numeric_features[0]) if malicious_numeric_features else 'N/A'}).")
        return True

    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Failed to load or parse ML definitions from {filepath}: {e}. ML scanning will be disabled.")
        return False

# ---------------- Result logging ----------------
def log_scan_result(md5: str, result: dict[str, any], from_cache: bool = False):
    is_threat = (
        result.get('clamav_result', {}).get('status') == 'threat_found' or
        len(result.get('yara_matches', [])) > 0 or
        result.get('ml_result', {}).get('is_malicious', False)
    )
    if not is_threat:
        return

    source = "(From Cache)" if from_cache else "(New Scan)"
    logging.info(
        f"\n{'='*50}\n"
        f"!!! MALWARE DETECTED !!! {source}\n"
        f"File MD5: {md5}\n"
        f"{'='*50}\n"
        f"STATUS: {result.get('status')}\n"
        f"--- ClamAV ---\n{result.get('clamav_result')}\n"
        f"--- YARA ---\n{result.get('yara_matches')}\n"
        f"--- ML ---\n{result.get('ml_result')}\n"
        f"{'='*50}"
    )

# ---------------- Cache helpers ----------------
def get_code_version_hash():
    """Generate a hash of critical ML functions to detect code changes."""
    try:
        code_content = ''.join([
            inspect.getsource(calculate_vector_similarity),
            inspect.getsource(scan_file_with_machine_learning_ai),
            inspect.getsource(load_ml_definitions)
        ])
        return hashlib.md5(code_content.encode()).hexdigest()[:8]
    except Exception:
        return "unknown"

def _make_complete_cacheable_result(result: Dict[str, Any]) -> Dict[str, Any]:
    r = copy.deepcopy(result)
    r['_cache_timestamp'] = time.time()
    r['_clamav_db_version'] = get_clamav_db_version()
    return r

def load_scan_cache(filepath: str) -> Dict[str, Any]:
    if not os.path.exists(filepath):
        return {'_clamav_db_version': get_clamav_db_version()}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        current_db_version = get_clamav_db_version()
        if cache_data.get('_clamav_db_version') != current_db_version:
            logging.info(f"ClamAV DB updated. Cache results will be refreshed.")
        return cache_data
    except Exception as e:
        logging.warning(f"Could not read cache file '{filepath}': {e}")
        return {'_clamav_db_version': get_clamav_db_version()}

def save_scan_cache(filepath: str, new_data: Dict[str, Any], lock: Lock):
    """Process-safe merge + save of scan cache using a multiprocessing Lock."""
    try:
        with lock:
            existing = load_scan_cache(filepath) if os.path.exists(filepath) else {}
            existing.update(new_data)
            existing['_clamav_db_version'] = get_clamav_db_version()
            existing['_last_save'] = time.time()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(existing, f, indent=4)
    except Exception as e:
        logging.error(f"Could not merge/save cache: {e}")

def process_file(file_to_scan: str, shared_cache: dict, cache_lock: Lock) -> Tuple[str, bool]:
    """Processes a single file. Relies on worker-initialized globals."""
    if not os.path.exists(file_to_scan):
        return "", False

    md5_hash = calculate_md5(file_to_scan)
    if not md5_hash:
        return "", False

    cached_result = shared_cache.get(md5_hash)
    current_clamav_version = get_clamav_db_version()
    
    # Decide if a full rescan is needed
    needs_rescan = True
    if cached_result:
        cached_db_ver = cached_result.get('_clamav_db_version')
        if cached_db_ver == current_clamav_version:
            needs_rescan = False

    if not needs_rescan:
        log_scan_result(md5_hash, cached_result, from_cache=True)
        is_threat = (cached_result.get('clamav_result', {}).get('status') == 'threat_found' or
                     len(cached_result.get('yara_matches', [])) > 0 or
                     cached_result.get('ml_result', {}).get('is_malicious', False))
        return md5_hash, is_threat

    # Perform fresh scan
    clamav_res = scan_file_with_clamav_hybrid(file_to_scan)
    yara_res = scan_file_with_yara_hybrid(file_to_scan)
    is_malicious, definition, sim = scan_file_with_ml_hybrid(file_to_scan)
    ml_result = {'is_malicious': is_malicious, 'definition': definition, 'similarity': float(sim)}
    
    result = {
        'status': 'scanned',
        'file_type': check_file_type_with_die(file_to_scan),
        'clamav_result': clamav_res,
        'yara_matches': yara_res,
        'ml_result': ml_result,
        '_scan_timestamp': time.time(),
    }
    
    is_threat = (clamav_res.get('status') == 'threat_found' or
                 len(yara_res) > 0 or
                 ml_result.get('is_malicious', False))

    log_scan_result(md5_hash, result, from_cache=False)
    
    cache_update = {md5_hash: _make_complete_cacheable_result(result)}
    save_scan_cache(SCAN_CACHE_FILE, cache_update, cache_lock)
    
    return md5_hash, is_threat

def get_memory_cache_stats() -> Dict[str, int]:
    return {
        'clamav': len(_memory_cache_clamav),
        'yara': len(_memory_cache_yara),
        'ml': len(_memory_cache_ml)
    }

def clear_memory_caches():
    _memory_cache_clamav.clear()
    _memory_cache_yara.clear()
    _memory_cache_ml.clear()

def _extract_rule_name_from_match(m):
    if isinstance(m, dict): return m.get("rule") or m.get("identifier")
    return str(m) if m else None

def collect_false_positive_rules_from_cache(cache_dict, already_excluded=None, min_frequency=1):
    rule_counter = Counter()
    excluded = set(already_excluded or [])
    for entry in cache_dict.values():
        if not isinstance(entry, dict): continue
        is_clean = (entry.get("clamav_result", {}).get("status") != "threat_found" and 
                    not (entry.get("ml_result") or {}).get("is_malicious"))
        if entry.get("yara_matches") and is_clean:
            for rname in {_extract_rule_name_from_match(m) for m in entry["yara_matches"]}:
                if rname and rname not in excluded:
                    rule_counter[rname] += 1
    return Counter({r: c for r, c in rule_counter.items() if c >= min_frequency})

def auto_append_excluded_rules(cache_path, excluded_rules_file, backup=True, min_frequency=1):
    cache = load_scan_cache(cache_path)
    existing = load_excluded_rules(excluded_rules_file)
    candidates = collect_false_positive_rules_from_cache(cache, already_excluded=existing, min_frequency=min_frequency)
    if not candidates: return [], candidates

    if backup and os.path.exists(excluded_rules_file):
        shutil.copy(excluded_rules_file, excluded_rules_file + ".bak")

    added = []
    with open(excluded_rules_file, "a", encoding="utf-8") as fh:
        for rule in sorted(candidates.keys()):
            if rule not in existing:
                fh.write(rule.strip() + "\n")
                added.append(rule)
    return added, candidates

def main():
    # --- Main Process Setup ---
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        filename=LOG_FILE,
                        filemode='w')
    
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    parser = argparse.ArgumentParser(description="HydraDragon Antivirus Scanner")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("--clear-cache", action="store_true", help="Clear disk scan cache before running")
    parser.add_argument("--false-positive-test", action="store_true", help="Auto-exclude YARA rules from clean files")
    parser.add_argument("--workers", type=int, default=os.cpu_count(), help="Number of worker processes")
    args = parser.parse_args()

    if args.clear_cache and os.path.exists(SCAN_CACHE_FILE):
        os.remove(SCAN_CACHE_FILE)
        logging.info("Disk cache cleared.")

    setup_directories()
    excluded_yara_rules = load_excluded_rules(EXCLUDED_RULES_FILE)
    
    files_to_scan = []
    if os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for fname in files:
                files_to_scan.append(os.path.join(root, fname))
    else:
        files_to_scan.append(args.path)

    total_files = len(files_to_scan)
    logging.info(f"Discovered {total_files} files. Starting scan with {args.workers} workers.")
    
    # --- Multiprocessing Execution ---
    malicious_count = 0
    start_wall = time.perf_counter()

    with Manager() as manager:
        log_q = manager.Queue()
        listener_thread = threading.Thread(target=log_listener, args=(log_q,))
        listener_thread.start()

        shared_cache = manager.dict(load_scan_cache(SCAN_CACHE_FILE))
        cache_lock = manager.Lock()

        init_args = (log_q, excluded_yara_rules, ML_RESULTS_JSON, YARA_RULES_DIR)
        
        with ProcessPoolExecutor(max_workers=args.workers, initializer=worker_init, initargs=init_args) as executor:
            futures = {executor.submit(process_file, f, shared_cache, cache_lock): f for f in files_to_scan}
            
            for fut in tqdm(as_completed(futures), total=total_files, desc="Scanning files", unit="file"):
                try:
                    _, is_threat = fut.result()
                    if is_threat:
                        malicious_count += 1
                except Exception as e:
                    logging.error(f"A file scan generated an exception: {e}", exc_info=True)

        log_q.put(None)
        listener_thread.join()

    # --- Final Summary ---
    wall_elapsed = time.perf_counter() - start_wall
    logging.info(f"\n{'='*60}\nFINAL SCAN SUMMARY\n"
                 f"  Total Malicious Files: {malicious_count}\n"
                 f"  Total Clean Files: {total_files - malicious_count}\n"
                 f"  Execution Time: {wall_elapsed:.2f}s\n{'='*60}")
    
    if args.false_positive_test:
        logging.info("Running auto false-positive test...")
        added, _ = auto_append_excluded_rules(SCAN_CACHE_FILE, EXCLUDED_RULES_FILE)
        if added:
            logging.info(f"Auto-excluded {len(added)} YARA rules.")
        else:
            logging.info("No new rules to auto-exclude.")

if __name__ == "__main__":
    main()
