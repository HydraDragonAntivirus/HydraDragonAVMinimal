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
from typing import List, Dict, Any, Optional, Set, Tuple
import inspect
import copy
import numpy as np
import capstone

# Add ClamAV subfolder to Python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Add local ClamAV folder to DLL search path if it exists
local_clamav = os.path.join(BASE_DIR, 'clamav')
if os.path.exists(local_clamav):
    os.add_dll_directory(local_clamav)
    current_path = os.environ.get('PATH', '')
    if local_clamav not in current_path:
        os.environ['PATH'] = local_clamav + os.pathsep + current_path
    print(f"Added local ClamAV path to search: {local_clamav}")

# ---------------- Logging ----------------
LOG_FILE = 'antivirus.log'
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE,
                    filemode='w')
logging.captureWarnings(True)
print(f"Script starting - detailed log: {LOG_FILE}")

# ---------------- Optional third-party flags ----------------
_have_yara = False
_have_yara_x = False
_have_chardet = False

try:
    import yara
    _have_yara = True
except Exception:
    logging.warning("yara-python not available - YARA scanning disabled.")

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
ML_RESULTS_JSON = os.path.join(BASE_DIR, 'machine_learning', 'results.json')
SCAN_CACHE_FILE = os.path.join(BASE_DIR, 'scan_cache.json')

# Limits / concurrency
DEFAULT_MAX_WORKERS = max(2, (os.cpu_count() or 1))
INPROC_SEMAPHORE = threading.Semaphore(max(1, min(8, DEFAULT_MAX_WORKERS)))  # protect inproc calls if needed

# YARA order
ORDERED_YARA_FILES = [
    'yaraxtr.yrc',
    'valhalla-rules.yrc',
    'icewater.yrc',
    'machine_learning.yrc',
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

def load_scan_cache(filepath: str) -> Dict[str, Any]:
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Could not read cache file: {e}")
    return {}

def save_scan_cache(filepath: str, cache: Dict[str, Any]):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        logging.error(f"Could not save cache file: {e}")

# ---------------- YARA preload ----------------
def preload_yara_rules(rules_dir: str):
    global _global_yara_compiled
    for rule_filename in ORDERED_YARA_FILES:
        rule_filepath = os.path.join(rules_dir, rule_filename)
        if not os.path.exists(rule_filepath):
            logging.info(f"YARA rule not found (skipping): {rule_filepath}")
            continue
        try:
            if rule_filename == 'yaraxtr.yrc' and _have_yara_x:
                # pass file object to deserialize_from
                with open(rule_filepath, "rb") as f:
                    rules = yara_x.Rules.deserialize_from(f)
                    _global_yara_compiled[rule_filename] = rules
            else:
                if not _have_yara:
                    logging.warning(f"yara-python not available; cannot load {rule_filename}")
                    continue
                # works for precompiled YARA rules
                compiled = yara.load(rule_filepath)
                _global_yara_compiled[rule_filename] = compiled
            logging.info(f"Preloaded YARA rules: {rule_filename}")
        except Exception as e:
            logging.error(f"Failed to preload YARA rule {rule_filename}: {e}")

# ---------------- In-process ClamAV init (STRICT) ----------------
def init_inproc_clamav(dbpath: Optional[str] = None, autoreload: bool = True) -> None:
    """
    Strictly require the clamav.py module to be in the same directory as the script.
    Checks for libclamav.dll and database in a 'clamav' subfolder.
    On any failure, exit the script - there are NO fallbacks.
    """
    global CLAMAV_INPROC, CLAMAV_MODULE

    # Check for clamav.py in the script's directory
    clamav_py_path = os.path.join(BASE_DIR, "clamav.py")
    if not os.path.exists(clamav_py_path):
        logging.critical(f"clamav.py not found: {clamav_py_path}")
        sys.exit(2)

    # Define the path for ClamAV assets (DLLs, database)
    clamav_assets_dir = os.path.join(BASE_DIR, "clamav")
    if not os.path.exists(clamav_assets_dir):
        logging.critical(f"Required 'clamav' subfolder not found: {clamav_assets_dir}")
        sys.exit(2)

    # Check libclamav.dll
    libclamav_dll = os.path.join(clamav_assets_dir, "libclamav.dll")
    if not os.path.exists(libclamav_dll):
        logging.critical(f"libclamav.dll not found: {libclamav_dll}")
        sys.exit(2)

    try:
        # The script's directory is automatically in Python's path
        import clamav as _clamav_pkg
        CLAMAV_MODULE = _clamav_pkg
    except Exception as e:
        logging.critical(f"Cannot import clamav.py: {e}")
        sys.exit(2)

    Scanner = getattr(CLAMAV_MODULE, "Scanner", None)
    if Scanner is None:
        logging.critical("ClamAV module does not expose Scanner class")
        sys.exit(3)

    # Database path default
    if dbpath is None:
        dbpath = os.path.join(clamav_assets_dir, "database")

    # Instantiate scanner with DLL path + database path
    try:
        CLAMAV_INPROC = Scanner(libclamav_dll, dbpath=dbpath, autoreload=autoreload)
        if not CLAMAV_INPROC or not getattr(CLAMAV_INPROC, "engine", None):
            logging.critical("Failed to initialize ClamAV engine")
            sys.exit(4)
    except Exception as e:
        logging.critical(f"Failed to instantiate Scanner: {e}")
        sys.exit(4)

    logging.info("Successfully initialized in-process ClamAV Scanner.")

# ---------------- Inproc scan wrapper (MODIFIED) ----------------
def scan_file_with_clamav(path: str) -> Dict[str, Any]:
    """Scans a file using the high-level clamav.py Scanner instance."""
    if CLAMAV_INPROC is None:
        raise RuntimeError("CLAMAV_INPROC Scanner not initialized")
    
    if CLAMAV_MODULE is None:
         raise RuntimeError("CLAMAV_MODULE not initialized")

    try:
        # Call the high-level scanFile method from the Scanner class
        ret, virus_name = CLAMAV_INPROC.scanFile(path)

        # Interpret the result and return it in the expected dictionary format
        if ret == CLAMAV_MODULE.CL_CLEAN:
            return {'status': 'clean', 'details': 'No threat found.'}
        elif ret == CLAMAV_MODULE.CL_VIRUS:
            return {'status': 'threat_found', 'details': virus_name or 'Unknown'}
        else:
            # Try to get a descriptive error message
            try:
                err_msg = CLAMAV_INPROC.get_error_message(ret)
            except Exception:
                err_msg = f"ClamAV error code: {ret}"
            return {'status': 'error', 'details': err_msg}

    except Exception as e:
        logging.exception(f"ClamAV scan via wrapper failed for {path}")
        return {'status': 'error', 'details': str(e)}

# ---------------- DIE heuristics & YARA scanning ----------------
def is_plain_text(data: bytes, null_byte_threshold: float = 0.01, printable_threshold: float = 0.95) -> bool:
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
    Sequential YARA scanning. For YARA-X we do NOT spawn a thread here because
    yara_x.Scanner objects are not sendable across threads.
    """
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
                    with open(file_path, "rb") as f:
                        data_content = f.read()
                    if not data_content:
                        continue

                # Run worker *in the same thread* (no Thread creation)
                try:
                    if compiled:
                        # compiled might be a Rules object or a Scanner.
                        # If it's a Scanner and was created on this thread, compiled.scan is fine.
                        # If compiled is a rules object (yara_x.Rules), rules.scan(...) also works.
                        # Always build a fresh Scanner in the current thread to avoid cross-thread issues
                        rules_obj = getattr(compiled, "rules", None)
                        if rules_obj is None:
                            rules_obj = compiled
                        scanner = yara_x.Scanner(rules=rules_obj)
                        scan_results = scanner.scan(data_content)
                        local_matched_rules = []
                        local_matched_results = []

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

                # Check if we found matches
                if results['matched_results']:
                    return results['matched_results']

            # --- yara-python mode ---
            else:
                if not _have_yara:
                    continue

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

# --- PE Analysis and Feature Extraction Functions ---

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
                logging.error(f"{file_path} is not a valid PE file.")
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
    logging.info(f"Starting machine learning scan for file: {file_path}")

    try:
        pe = pefile.PE(file_path)
        pe.close()
    except pefile.PEFormatError:
        logging.error(f"File {file_path} is not a valid PE file. Returning default value 'Unknown'.")
        return False, malware_definition, 0

    logging.info(f"File {file_path} is a valid PE file, proceeding with feature extraction.")

    file_numeric_features = pe_extractor.extract_numeric_features(file_path)
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
        except Exception:
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
                        except Exception:
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
                    except Exception:
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

        # Delay / other counts
        num_delay_imports = safe_len(delay_imports_list)

        # Rich header info (presence)
        rich_header = entry.get("rich_header", {}) or {}
        has_rich = int(bool(rich_header))

        # relocations count already computed above
        # bound imports count above

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
        malicious_numeric_features = []
        malicious_file_names = []
        for entry in malicious_entries:
            numeric, filename = entry_to_numeric(entry)
            malicious_numeric_features.append(numeric)
            malicious_file_names.append(filename)

        # Benign section
        benign_entries = ml_defs.get("benign", []) or []
        benign_numeric_features = []
        benign_file_names = []
        for entry in benign_entries:
            numeric, filename = entry_to_numeric(entry)
            benign_numeric_features.append(numeric)
            benign_file_names.append(filename)

        logging.info(f"[!] Loaded {len(malicious_numeric_features)} malicious and {len(benign_numeric_features)} benign ML definitions (vectors length = {len(malicious_numeric_features[0]) if malicious_numeric_features else 'N/A'}).")
        return True

    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Failed to load or parse ML definitions from {filepath}: {e}. ML scanning will be disabled.")
        return False

# ---------------- Result logging ----------------
def log_scan_result(md5: str, result: dict[str, any], from_cache: bool = False):
    # Determine if the result indicates a threat
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
    try:
        # Ensure code version is always saved
        cache['_code_version'] = get_code_version_hash()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        logging.error(f"Could not save cache file: {e}")

# --- helper: cacheable form (remove clamav_result before caching) ---
def _make_cacheable_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a deep-copied version of result suitable for caching:
    - Remove 'clamav_result'
    - Ensure 'yara_matches' and 'ml_result' exist
    - Mark it as cached without ClamAV
    """
    r = copy.deepcopy(result)
    
    # Remove ClamAV result safely
    r.pop('clamav_result', None)
    
    # Ensure YARA and ML keys exist
    r.setdefault('yara_matches', [])
    r.setdefault('ml_result', {'is_malicious': False, 'definition': '', 'similarity': 0.0})
    
    # Mark as cached without ClamAV
    r['_cached_without_clamav'] = True
    
    return r

# ---------------- Per-file processing (REPLACE existing process_file) ----------------
def process_file(file_to_scan: str, excluded_yara_rules: Set[str]):
    """
    Process a single file.
    - ClamAV results are never cached.
    - On cache hit: use cached YARA+ML but always re-run ClamAV.
    - ML scan applies 0.93 benign score threshold.
    """
    global malicious_file_count, benign_file_count
    
    if not os.path.exists(file_to_scan):
        logging.warning(f"File not found: {file_to_scan}")
        return

    # --- File stat ---
    try:
        st = os.stat(file_to_scan)
        stat_key = f"{st.st_size}:{st.st_mtime_ns}"
    except Exception:
        stat_key = None

    # --- Load cache ---
    cache = load_scan_cache(SCAN_CACHE_FILE)

    # --- MD5 ---
    md5_hash = calculate_md5(file_to_scan)
    if not md5_hash:
        return

    # --- CACHE HIT ---
    if md5_hash in cache and not md5_hash.startswith('_'):
        cached = cache[md5_hash]
        
        # Always rerun ClamAV
        try:
            clamav_res = scan_file_with_clamav(file_to_scan)
        except Exception as e:
            clamav_res = {'status': 'error', 'details': f'ClamAV error on cache-hit rescan: {e}'}

        merged = copy.deepcopy(cached)
        merged['clamav_result'] = clamav_res
        merged['_stat'] = stat_key

        log_scan_result(md5_hash, merged, from_cache=True)

        is_threat = (
            (clamav_res.get('status') == 'threat_found') or
            (len(cached.get('yara_matches', [])) > 0) or
            (cached.get('ml_result', {}).get('is_malicious') is True)
        )
        with file_counter_lock:
            if is_threat:
                malicious_file_count += 1
            else:
                benign_file_count += 1
        return

    # --- File size check ---
    size = os.path.getsize(file_to_scan)
    if size == 0:
        result = {
            'status': 'skipped',
            'reason': 'Empty file',
            'file_type': 'Empty',
            'clamav_result': {'status': 'skipped', 'details': 'File is empty'},
            'yara_matches': [],
            'ml_result': {'is_malicious': False, 'definition': 'Skipped - Empty file', 'similarity': 0.0},
            '_stat': stat_key
        }
        with file_counter_lock:
            benign_file_count += 1
        log_scan_result(md5_hash, result)
        cache[md5_hash] = _make_cacheable_result(result)
        save_scan_cache(SCAN_CACHE_FILE, cache)
        return

    # --- File type detection ---
    file_type = check_file_type_with_die(file_to_scan)

    # --- ClamAV scan ---
    clamav_res = scan_file_with_clamav(file_to_scan)

    if clamav_res.get('status') == 'threat_found':
        result = {
            'status': 'scanned',
            'file_type': file_type,
            'clamav_result': clamav_res,
            'yara_matches': [],
            'ml_result': {'is_malicious': False, 'definition': 'Not Scanned', 'similarity': 0.0},
            '_stat': stat_key
        }
        with file_counter_lock:
            malicious_file_count += 1
        log_scan_result(md5_hash, result)
        return

    # --- YARA scan ---
    yara_res = scan_file_with_yara_sequentially(file_to_scan, excluded_yara_rules)

    if yara_res:
        result = {
            'status': 'scanned',
            'file_type': file_type,
            'clamav_result': clamav_res,
            'yara_matches': yara_res,
            'ml_result': {'is_malicious': False, 'definition': 'Not Scanned', 'similarity': 0.0},
            '_stat': stat_key
        }
        with file_counter_lock:
            malicious_file_count += 1
        log_scan_result(md5_hash, result)
        cache[md5_hash] = _make_cacheable_result(result)
        save_scan_cache(SCAN_CACHE_FILE, cache)
        return

    # --- ML scan with 0.93 threshold ---
    is_malicious, definition, sim = scan_file_with_machine_learning_ai(file_to_scan)

    # If your ML function can return matched rules, do this:
    matched_rules = getattr(scan_file_with_machine_learning_ai, "last_matched_rules", [])

    if matched_rules:
        logging.warning(f"ML matched rules for {file_to_scan}: {matched_rules}")

    if is_malicious and sim < 0.93:
        ml_result = {'is_malicious': True, 'definition': definition, 'similarity': float(sim)}
        with file_counter_lock:
            malicious_file_count += 1
    else:
        ml_result = {'is_malicious': False, 'definition': definition, 'similarity': float(sim)}

    # --- Final result ---
    result = {
        'status': 'scanned',
        'file_type': file_type,
        'clamav_result': clamav_res,
        'yara_matches': yara_res,
        'ml_result': ml_result,
        '_stat': stat_key
    }

    with file_counter_lock:
        if ml_result['is_malicious'] or yara_res or clamav_res.get('status') == 'threat_found':
            malicious_file_count += 1
        else:
            benign_file_count += 1

    log_scan_result(md5_hash, result)
    cache[md5_hash] = _make_cacheable_result(result)
    save_scan_cache(SCAN_CACHE_FILE, cache)

    logging.info(f"Finished processing {os.path.basename(file_to_scan)}")

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="HydraDragon (IN-PROCESS libclamav only, NO TIMEOUTS) + YARA + ML")
    parser.add_argument("--clear-cache", action="store_true", help="Clear scan cache")
    parser.add_argument("path", nargs='?', help="Path to file or directory to scan")
    parser.add_argument(
    "--false-positive-test",
    action="store_true",
    help="Automatically exclude YARA rules that trigger but ML+ClamAV say clean" 
    )
    args = parser.parse_args()

    start_wall = time.perf_counter()
    setup_directories()

    if args.clear_cache and os.path.exists(SCAN_CACHE_FILE):
        os.remove(SCAN_CACHE_FILE)
        logging.info("Cache cleared manually.")

    # Initialize 64-bit safe in-process ClamAV
    db_abs = os.path.abspath("ClamAV/database")
    init_inproc_clamav(dbpath=db_abs, autoreload=True)

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
        futures = {executor.submit(process_file, f, excluded_yara_rules): f for f in files_to_scan}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=total_files, desc="Scanning files", unit="file"):
            fpath = futures[fut]
            try:
                fut.result()  # result should increment counters inside process_file
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

if __name__ == "__main__":
    main()
