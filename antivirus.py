#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import time
import json
import hashlib
import string
import inspect
import subprocess
import threading
import itertools
import ctypes
from typing import List, Dict, Any, Optional, Set, Tuple, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
import capstone
import yara
import yara_x
import pefile
import chardet
from tqdm import tqdm
import clamav
from hydra_logger import script_dir, logger

thread_lock = threading.Lock()

# ---------------- Paths & configuration ----------------
YARA_RULES_DIR = os.path.join(script_dir, 'yara')
EXCLUDED_RULES_FILE = os.path.join(script_dir, 'excluded', 'excluded_rules.txt')
ML_RESULTS_JSON = os.path.join(script_dir, 'machine_learning', 'results.json')
SCAN_CACHE_FILE = os.path.join(script_dir, 'scan_cache.json')

# ClamAV base folder path
clamav_folder = os.path.join(script_dir, "ClamAV")
libclamav_path = os.path.join(clamav_folder, "libclamav.dll")
clamav_database_directory_path = os.path.join(clamav_folder, "database")

detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")

# Global cache: md5 -> (die_output, plain_text_flag)
die_cache: dict[str, tuple[str, bool]] = {}

# Separate cache for "binary-only" DIE results
binary_die_cache: dict[str, str] = {}

# YARA order
ORDERED_YARA_FILES = [
    'yaraxtr.yrc',
    'valhalla-rules.yrc',
    'icewater.yrc',
    'machine_learning.yrc',
    'clean_rules.yrc'
]
_global_yara_compiled: Dict[str, Any] = {}

# Globals for worker processes
excluded_yara_rules = None
_global_db_state_hash: Optional[str] = None
clamav_scanner: Optional[clamav.Scanner] = None

# ---------------- Utility functions ----------------
def is_admin():
    """Check if the script is running with administrative privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def compute_md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def get_database_state_hash(clamav_db_path: str, yara_rules_dir: str, ml_defs_path: str) -> str:
    """Generates a hash representing the state of all signature databases."""
    hasher = hashlib.md5()
    paths_to_check = []

    # ClamAV databases
    if os.path.isdir(clamav_db_path):
        for root, _, files in os.walk(clamav_db_path):
            for f in files:
                paths_to_check.append(os.path.join(root, f))
    
    # YARA rules
    if os.path.isdir(yara_rules_dir):
        for f in ORDERED_YARA_FILES:
            paths_to_check.append(os.path.join(yara_rules_dir, f))

    # ML definitions
    paths_to_check.append(ml_defs_path)

    for p in sorted(paths_to_check):
        if os.path.exists(p):
            try:
                stat = os.stat(p)
                # Use path, mtime, and size to represent state
                file_state = f"{p}:{stat.st_mtime_ns}:{stat.st_size}\n"
                hasher.update(file_state.encode())
            except OSError:
                continue # Ignore files we can't access
    
    return hasher.hexdigest()

def load_scan_cache(filepath: str, lock: threading.Lock = thread_lock) -> Dict[str, Any]:
    """
    Load scan cache from JSON file with error handling and best-effort recovery.
    Uses `lock` to avoid races between threads in the same process.
    """
    if not os.path.exists(filepath):
        return {}

    # Protect read with the process-local lock so threads don't read while we write.
    with lock:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except json.JSONDecodeError as e:
            logger.warning(f"Cache file is corrupted (JSON error): {e}. Attempting recovery.")
            # If a temp file exists, try that as a recovery source.
            tmp_path = filepath + ".tmp"
            if os.path.exists(tmp_path):
                try:
                    with open(tmp_path, 'r', encoding='utf-8') as tf:
                        tmp_content = tf.read().strip()
                        if tmp_content:
                            recovered = json.loads(tmp_content)
                            # Replace broken cache with recovered tmp atomically
                            try:
                                os.replace(tmp_path, filepath)
                                logger.info(f"Recovered cache from tmp file and replaced {filepath}")
                                return recovered
                            except Exception as re:
                                logger.warning(f"Failed to replace corrupted cache with tmp: {re}")
                                return recovered
                except Exception as re:
                    logger.warning(f"Failed to read tmp cache file for recovery: {re}")

            # Could not recover: remove corrupted cache and start fresh
            try:
                os.remove(filepath)
                logger.info(f"Removed corrupted cache file: {filepath}")
            except Exception:
                logger.exception("Failed to remove corrupted cache file")
            return {}
        except FileNotFoundError:
            # Raced with a removal; treat as empty
            return {}
        except Exception as e:
            logger.warning(f"Could not read cache file: {e}")
            return {}

def save_scan_cache(filepath: str, cache: Dict[str, Any], lock: threading.Lock = thread_lock) -> None:
    """
    Atomically write cache to disk using a temp file and os.replace.
    Caller may pass a lock (defaults to module thread_lock) to protect against concurrent threads.
    """
    # Make sure target dir exists
    dest_dir = os.path.dirname(filepath) or "."
    os.makedirs(dest_dir, exist_ok=True)

    tmp_fd = None
    tmp_path = None
    with lock:
        try:
            # Use tempfile in same directory for atomic replace on same filesystem
            fd, tmp_path = tempfile.mkstemp(prefix=".cache-", dir=dest_dir, text=True)
            tmp_fd = fd
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())   # ensure data hit disk
            # atomic replace
            os.replace(tmp_path, filepath)
        except Exception as e:
            logger.error(f"Could not save cache file atomically: {e}")
            # cleanup tmp if needed
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

# ---------------- Engine Initialization ----------------
def initialize_clamav() -> clamav.Scanner:
    """Initializes the ClamAV scanner engine."""
    logger.info("Initializing ClamAV engine...")
    try:
        scanner = clamav.Scanner(libclamav_path=libclamav_path, dbpath=clamav_database_directory_path)
        logger.info("ClamAV engine initialized successfully.")
        return scanner
    except Exception as e:
        logger.critical(f"Failed to initialize ClamAV engine: {e}", exc_info=True)
        sys.exit(f"CRITICAL: Could not load ClamAV engine. Exiting. Error: {e}")

def _load_one_yara_rule(rule_filename: str, rules_dir: str) -> Optional[Tuple[str, Any]]:
    """Helper function to load a single YARA rule file."""
    rule_filepath = os.path.join(rules_dir, rule_filename)
    if not os.path.exists(rule_filepath):
        logger.info(f"YARA rule not found (skipping): {rule_filepath}")
        return None
    try:
        if rule_filename == 'yaraxtr.yrc':
            with open(rule_filepath, "rb") as f:
                rules = yara_x.Rules.deserialize_from(f)
                return rule_filename, rules
        else:
            compiled = yara.load(rule_filepath)
            return rule_filename, compiled
    except Exception as e:
        logger.error(f"Failed to preload YARA rule {rule_filename}: {e}")
        return None

def preload_yara_rules(rules_dir: str, max_workers: int = 10):
    """Preloads all YARA rule files in parallel."""
    global _global_yara_compiled
    logger.info("Preloading YARA rules in parallel...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        tasks = {executor.submit(_load_one_yara_rule, filename, rules_dir): filename for filename in ORDERED_YARA_FILES}
        
        temp_results = {}
        for future in as_completed(tasks):
            result = future.result()
            if result:
                rule_filename, compiled_rules = result
                temp_results[rule_filename] = compiled_rules
                logger.info(f"Successfully loaded YARA rule: {rule_filename}")

    # Ensure the final compiled rules are in the correct order for sequential scanning
    with thread_lock:
        _global_yara_compiled.clear()
        for rule_filename in ORDERED_YARA_FILES:
            if rule_filename in temp_results:
                _global_yara_compiled[rule_filename] = temp_results[rule_filename]

    logger.info("All YARA rules preloaded.")

def reload_clamav_database():
    """
    Reloads the ClamAV engine with the updated database.
    Required after updating signatures.
    """
    global clamav_scanner
    if not clamav_scanner:
        logger.error("ClamAV scanner not initialized, cannot reload database.")
        return
    try:
        logger.info("Reloading ClamAV database...")
        clamav_scanner.loadDB()
        logger.info("ClamAV database reloaded successfully.")
    except Exception as ex:
        logger.error(f"Failed to reload ClamAV database: {ex}")

def scan_file_with_clamav(file_path):
    """Scan file using the in-process ClamAV wrapper (scanner) and return virus name or 'Clean'."""
    global clamav_scanner
    if not clamav_scanner:
        logger.error(f"ClamAV scanner not initialized. Cannot scan {file_path}.")
        return "Error"
    try:
        file_path = os.path.abspath(file_path)
        ret, virus_name = clamav_scanner.scanFile(file_path)

        if ret == clamav.CL_CLEAN:
            return "Clean"
        elif ret == clamav.CL_VIRUS:
            return virus_name or "Infected"
        else:
            logger.error(f"Unexpected ClamAV scan result for {file_path}: {ret}")
            return "Error"
    except Exception as ex:
        logger.error(f"Error scanning file {file_path}: {ex}")
        return "Error"

# ---------------- DIE heuristics & YARA scanning ----------------
def is_plain_text(data: bytes,
                  null_byte_threshold: float = 0.01,
                  printable_threshold: float = 0.95) -> bool:
    """
    Heuristic: data is plain text if
      1. It contains very few null bytes,
      2. A high fraction of bytes are printable or common whitespace,
      3. And it decodes cleanly in some text encoding (e.g. UTF-8, Latin-1).

    :param data:       raw file bytes
    :param null_byte_threshold:
                       max fraction of bytes that can be zero (0x00)
    :param printable_threshold:
                       min fraction of bytes in printable + whitespace set
    """
    if not data:
        return True

    # 1) Null byte check
    nulls = data.count(0)
    if nulls / len(data) > null_byte_threshold:
        return False

    # 2) Printable char check
    printable = set(bytes(string.printable, 'ascii'))
    count_printable = sum(b in printable for b in data)
    if count_printable / len(data) < printable_threshold:
        return False

    # 3) Try a text decoding
    #    Use chardet to guess encoding
    guess = chardet.detect(data)
    enc = guess.get('encoding') or 'utf-8'
    try:
        data.decode(enc)
        return True
    except (UnicodeDecodeError, LookupError):
        return False

def analyze_file_with_die(file_path):
    """
    Runs Detect It Easy (DIE) on the given file once and returns the DIE output (plain text).
    The output is also saved to a unique .txt file and displayed to the user.
    """
    try:
        # Run the DIE command once with the -p flag for plain output
        result = subprocess.run(
            [detectiteasy_console_path, "-p", file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore"
        )

        return result.stdout

    except subprocess.SubprocessError as ex:
        error_msg = f"Error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}"
        logger.error(error_msg)
        return None
    except Exception as ex:
        error_msg = f"General error in {inspect.currentframe().f_code.co_name} while running Detect It Easy for {file_path}: {ex}"
        logger.error(error_msg)
        return None

def get_die_output_binary(path: str, file_md5: Optional[str] = None) -> str:
    """
    Returns die_output for a non plain text file, caching by content MD5.
    (Assumes the file isn't plain text, so always calls analyze_file_with_die()
     on cache miss.)
    """
    if file_md5 is None:
        file_md5 = compute_md5(path)
    if file_md5 in binary_die_cache:
        return binary_die_cache[file_md5]

    # First time for this content: run DIE and cache
    die_output = analyze_file_with_die(path)
    binary_die_cache[file_md5] = die_output
    return die_output

def get_die_output(path: str, file_md5: Optional[str] = None) -> Tuple[str, bool]:
    """
    Returns (die_output, plain_text_flag), caching results by content MD5.
    Uses get_die_output_binary() if the file is not plain text.
    """
    if file_md5 is None:
        file_md5 = compute_md5(path)
    if file_md5 in die_cache:
        return die_cache[file_md5]

    # First time for this content
    with open(path, "rb") as f:
        peek = f.read(8192)

    if is_plain_text(peek):
        die_output = "Binary\n    Format: plain text"
        plain_text_flag = True
    else:
        die_output = get_die_output_binary(path, file_md5=file_md5)  # delegate to binary cache
        plain_text_flag = False  # skip text detection here

    die_cache[file_md5] = (die_output, plain_text_flag)
    return die_output, plain_text_flag

def is_file_fully_unknown(die_output: str) -> bool:
    """
    Determines whether DIE output indicates an unrecognized binary file,
    ignoring any trailing error messages or extra lines.

    Returns True if the first two non-empty, whitespace-stripped lines are:
        Binary
        Unknown: Unknown
    """
    if not die_output:
        logger.info("No DIE output provided.")
        return False

    # Normalize: split into lines, strip whitespace, drop empty lines
    lines = [line.strip() for line in die_output.splitlines() if line.strip()]

    # We only care about the first two markers; ignore anything after.
    if len(lines) >= 2 and lines[0] == "Binary" and lines[1] == "Unknown: Unknown":
        return True
    else:
        return False

def load_excluded_rules(filepath: str) -> List[str]:
    """
    Load excluded rules from a plain text file. One rule name per line.
    """
    try:
        # Load excluded rules from text file
        with open(filepath, "r") as excluded_file:
            excluded_rules = [line.strip() for line in excluded_file if line.strip()]
            logger.info(f"YARA Excluded Rules loaded: {len(excluded_rules)} rules")
            return excluded_rules
    except FileNotFoundError:
        logger.error(f"Excluded rules file not found: {filepath}")
        return []
    except Exception as ex:
        logger.error(f"Error loading excluded rules: {ex}")
        return []

def extract_yarax_match_details(rule, source):
    """Extract only rule name from YARA-X rule match."""
    return rule.identifier  # Return only the rule name as string

def scan_file_with_yara_sequentially(file_path: str, excluded_rules: Set[str]) -> List[str]:
    """
    Sequential YARA scanning that returns only rule names (not full details).
    """
    if excluded_rules is None:
        excluded_rules = set()
    
    data_content = None
    matched_rules = []

    for rule_filename in ORDERED_YARA_FILES:
        if rule_filename not in _global_yara_compiled:
            continue
        compiled = _global_yara_compiled[rule_filename]

        try:
            # --- yara-x mode ---
            if rule_filename == "yaraxtr.yrc":
                if data_content is None:
                    with open(file_path, "rb") as f:
                        data_content = f.read()
                    if not data_content:
                        continue

                try:
                    if compiled:
                        rules_obj = getattr(compiled, "rules", None)
                        if rules_obj is None:
                            rules_obj = compiled
                        scanner = yara_x.Scanner(rules=rules_obj)
                        scan_results = scanner.scan(data_content)

                        matching_rules = getattr(scan_results, "matching_rules", None)
                        if matching_rules is not None:
                            for rule in matching_rules:
                                rule_id = getattr(rule, 'identifier', None)
                                if rule_id is not None and rule_id not in excluded_rules:
                                    matched_rules.append(rule_id)  # Only append rule name

                        # Return immediately if matches found
                        if matched_rules:
                            return matched_rules

                except Exception as e:
                    logger.error(f"Error scanning with {rule_filename}: {e}")

            # --- yara-python mode ---
            else:
                matches = compiled.match(filepath=file_path)

                for m in matches:
                    if m.rule not in excluded_rules:
                        matched_rules.append(m.rule)  # Only append rule name

                if matched_rules:
                    return matched_rules

        except Exception as e:
            logger.error(f"Error during YARA scan with {rule_filename} on {file_path}: {e}")
            continue

    return matched_rules

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
            logger.error(f"Capstone disassembly failed: {e}")
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
            logger.error(f"Error retrieving TLS callback addresses: {e}")
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
            logger.error(f"Error analyzing TLS callbacks: {e}")
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
            logger.error(f"Error analyzing DOS stub: {e}")
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
            logger.error(f"Error analyzing certificates: {e}")
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
            logger.error(f"Error analyzing delay imports: {e}")
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
            logger.error(f"Error analyzing load config: {e}")
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
            logger.error(f"Error analyzing relocations: {e}")
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
                        logger.warning(f"Bound import {bound_import['name']} has no references.")

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logger.error(f"Error analyzing bound imports: {e}")
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
            logger.error(f"Error analyzing section characteristics: {e}")
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
            logger.error(f"Error analyzing extended headers: {e}")
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
            logger.error(f"Error analyzing Rich header: {e}")
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
            logger.error(f"Error analyzing overlay: {e}")
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
                logger.error(f"Error loading {file_path} as PE: {str(ex)}", exc_info=True)
                return None
            try:
                pe.parse_data_directories()
            except Exception:
                logger.debug(f"pe.parse_data_directories() failed for {file_path}", exc_info=True)

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
            logger.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None
        finally:
            # ensure PE handle is closed to release underlying file descriptor
            try:
                if pe is not None:
                    pe.close()
            except Exception:
                logger.debug(f"Failed to close pe for {file_path}", exc_info=True)

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

# Unified cache for all PE feature extractions (replaces both worm_scan_cache and any ML cache)
unified_pe_cache = {}

def get_cached_pe_features(file_path: str, file_md5: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Extract and cache PE file numeric features with unified caching.
    Returns cached features if available, otherwise extracts and caches them.
    Used by both ML scanning and worm detection.
    """
    # Calculate MD5 hash for caching
    if file_md5 is None:
        file_md5 = compute_md5(file_path)
    if not file_md5:
        return None

    # Check if we already have features for this MD5
    if file_md5 in unified_pe_cache:
        logger.debug(f"Using cached features for {file_path} (MD5: {file_md5})")
        return unified_pe_cache[file_md5]

    try:
        # Extract numeric features
        features = pe_extractor.extract_numeric_features(file_path)
        if features:
            # Cache the result with MD5 as key
            unified_pe_cache[file_md5] = features
            logger.debug(f"Cached features for {file_path} (MD5: {file_md5})")
            return features
        else:
            # Cache negative result too to avoid re-processing failed files
            unified_pe_cache[file_md5] = None
            return None

    except Exception as ex:
        logger.error(f"An error occurred while processing {file_path}: {ex}", exc_info=True)
        # Cache the failure to avoid repeated attempts
        unified_pe_cache[file_md5] = None
        return None

def scan_file_with_machine_learning_ai(file_path: str, file_md5: Optional[str] = None, threshold=0.86):
    """Scan a file for malicious activity using machine learning definitions loaded from JSON."""
    malware_definition = "Unknown"
    try:
        pe = pefile.PE(file_path)
        pe.close()
    except pefile.PEFormatError:
        return False, malware_definition, 0

    logger.info(f"File {file_path} is a valid PE file, proceeding with feature extraction.")

    # Use unified cache for feature extraction
    file_numeric_features = get_cached_pe_features(file_path, file_md5=file_md5)
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

            logger.critical(f"Malicious activity detected in {file_path}. Definition: {malware_definition}, similarity: {similarity}, rank: {rank}")

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
            logger.info(f"File {file_path} is classified as benign ({benign_definition}) with similarity: {nearest_benign_similarity}")
        else:
            malware_definition = "Unknown"

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
        logger.error(f"Machine learning definitions file not found: {filepath}. ML scanning will be disabled.")
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

        logger.info(f"[!] Loaded {len(malicious_numeric_features)} malicious and {len(benign_numeric_features)} benign ML definitions (vectors length = {len(malicious_numeric_features[0]) if malicious_numeric_features else 'N/A'}).")
        return True

    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load or parse ML definitions from {filepath}: {e}. ML scanning will be disabled.")
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
    
    # Format YARA matches as simple list of rule names
    yara_rules = result.get('yara_matches', [])
    if isinstance(yara_rules, list) and yara_rules:
        if isinstance(yara_rules[0], dict):
            # Old format with full details
            yara_display = [match.get('rule', 'Unknown') for match in yara_rules]
        else:
            # New format with just rule names
            yara_display = yara_rules
    else:
        yara_display = []
    
    logger.info(
        f"\n{'='*50}\n"
        f"!!! MALWARE DETECTED !!! {source}\n"
        f"File MD5: {md5}\n"
        f"{'='*50}\n"
        f"STATUS: {result.get('status')}\n"
        f"--- ClamAV ---\n{json.dumps(result.get('clamav_result'), indent=2)}\n"
        f"--- YARA ---\nMatched Rules: {', '.join(yara_display) if yara_display else 'None'}\n"
        f"--- ML ---\n{json.dumps(result.get('ml_result'), indent=2)}\n"
        f"{'='*50}"
    )

def discover_files_generator(target_path: str) -> Generator[str, None, None]:
    """
    Discovers files in the target path and yields them one by one
    to avoid loading the entire list into memory.
    """
    logger.info(f"Discovering files in {target_path}...")
    if os.path.isdir(target_path):
        for root, _, files in os.walk(target_path, onerror=lambda err: logger.error(f"os.walk error: {err}")):
            for fname in files:
                yield os.path.join(root, fname)
    elif os.path.exists(target_path):
        yield target_path

# ------------------ Worker (uses in-memory cache only) ------------------
def process_file_worker(file_to_scan: str, db_hash: str) -> Tuple[bool, Optional[Tuple[str, List[str]]]]:
    if not os.path.exists(file_to_scan):
        return False, None

    try:
        st = os.stat(file_to_scan)
        stat_key = f"{st.st_size}:{st.st_mtime_ns}"
    except Exception:
        return False, None

    cache_key = f"{file_to_scan}:{stat_key}"

    with thread_lock:
        cached_entry = global_scan_cache.get(cache_key)
        if cached_entry and cached_entry.get('_stat') == stat_key and global_scan_cache.get('_database_state_hash') == db_hash:
            is_threat = cached_entry['final_result']['status'] == 'threat_found'
            return is_threat, None

    # --- MD5 COMPUTATION ---
    try:
        md5_hash = compute_md5(file_to_scan)
    except Exception:
        md5_hash = "N/A"

    # --- CLAMAV ---
    clamav_result_raw = scan_file_with_clamav(file_to_scan)
    if clamav_result_raw == "Clean":
        clamav_res = {'status': 'clean', 'signature': None}
    elif clamav_result_raw == "Error":
        clamav_res = {'status': 'error', 'signature': None}
    else:
        clamav_res = {'status': 'threat_found', 'signature': clamav_result_raw}

    # --- DIE CHECK ---
    die_output, _ = get_die_output(file_to_scan, file_md5=md5_hash)
    if is_file_fully_unknown(die_output):
        final_result = {'status': 'clean', '_stat': stat_key}
    else:
        # --- YARA + ML ---
        yara_matches = scan_file_with_yara_sequentially(file_to_scan, excluded_yara_rules)
        ml_result = {'is_malicious': False, 'definition': 'Not Scanned', 'similarity': 0.0}
        if clamav_res['status'] != 'threat_found' and not yara_matches:
            try:
                is_malicious, definition, sim = scan_file_with_machine_learning_ai(file_to_scan, file_md5=md5_hash)
                ml_result = {'is_malicious': is_malicious, 'definition': definition, 'similarity': float(sim)}
            except Exception:
                pass

        is_threat = clamav_res['status'] == 'threat_found' or len(yara_matches) > 0 or ml_result['is_malicious']
        final_result = {
            'status': 'threat_found' if is_threat else 'clean',
            'clamav_result': clamav_res,
            'yara_matches': yara_matches,
            'ml_result': ml_result,
            '_stat': stat_key
        }

    # --- Update in-memory cache only ---
    with thread_lock:
        if global_scan_cache.get('_database_state_hash') != db_hash:
            global_scan_cache.clear()
            global_scan_cache['_database_state_hash'] = db_hash
        global_scan_cache[cache_key] = {'final_result': final_result, '_stat': stat_key}

    return final_result['status'] == 'threat_found', None


# ------------------ Scan Controller ------------------
def start_scan(files_to_scan, db_hash, max_workers):
    scanned_files = 0
    malicious_count = 0
    scan_results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_file_worker, f, db_hash): f for f in files_to_scan}

        with tqdm(total=len(files_to_scan), desc="Scanning files", unit="file") as pbar:
            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    result, _ = future.result()
                    scan_results[file_path] = result
                    if result:
                        malicious_count += 1
                except Exception as e:
                    scan_results[file_path] = False
                    logger.error(f"Error scanning {file_path}: {e}")
                scanned_files += 1
                pbar.update(1)

    logger.info(f"Scan complete. {scanned_files}/{len(files_to_scan)} files scanned. Threats: {malicious_count}")
    return scan_results

# ---------------- Main ----------------
def main():
    global excluded_yara_rules, _global_db_state_hash, global_scan_cache, clamav_scanner

    parser = argparse.ArgumentParser(description="HydraDragon Antivirus - Multi-engine scanner")
    parser.add_argument("--clear-cache", action="store_true", help="Clear scan cache before starting")
    parser.add_argument("--max-workers", type=int, default=1000)
    parser.add_argument("path", nargs="?", help="Path to file or directory to scan")
    args = parser.parse_args()

    # Initialize engines
    with ThreadPoolExecutor(max_workers=4) as executor:
        clamav_future = executor.submit(initialize_clamav)
        yara_future = executor.submit(preload_yara_rules, YARA_RULES_DIR)
        ml_future = executor.submit(load_ml_definitions, ML_RESULTS_JSON)
        excluded_rules_future = executor.submit(load_excluded_rules, EXCLUDED_RULES_FILE)

        clamav_scanner = clamav_future.result()
        yara_future.result()
        ml_future.result()
        excluded_yara_rules = set(excluded_rules_future.result())

    # Compute database hash
    _global_db_state_hash = get_database_state_hash(
        os.path.join(script_dir, "clamav", "database"), YARA_RULES_DIR, ML_RESULTS_JSON
    )

    # Discover files
    target = args.path
    files_to_scan = list(discover_files_generator(target))
    total_files = len(files_to_scan)
    logger.info(f"Found {total_files} files to scan.")

    # --- Load cache only (no reset, no save) ---
    try:
        global_scan_cache = load_scan_cache(SCAN_CACHE_FILE)
        logger.info("Loaded existing scan cache.")
    except Exception as e:
        logger.warning(f"Failed to load scan cache ({e}). Creating a new in-memory cache.")
        global_scan_cache = {'_database_state_hash': _global_db_state_hash}

    # Start scanning
    scan_results = start_scan(files_to_scan, _global_db_state_hash, args.max_workers)

    # Save final cache at the end
    try:
        save_scan_cache(SCAN_CACHE_FILE, global_scan_cache)
    except Exception as e:
        logger.error(f"Failed to save scan cache at end: {e}")

if __name__ == "__main__":
    main()
