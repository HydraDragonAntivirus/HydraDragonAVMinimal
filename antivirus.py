#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import time
import json
import hashlib
import string
import threading
from typing import List, Dict, Any, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
import capstone
import yara
import yara_x
import pefile
import chardet
import die
from tqdm import tqdm
import clamav
from hydra_logger import script_dir, logger

thread_lock = threading.Lock()

# ---------------- Paths & configuration ----------------
YARA_RULES_DIR = os.path.join(script_dir, 'yara')
EXCLUDED_RULES_FILE = os.path.join(script_dir, 'excluded', 'excluded_rules.txt')
ML_RESULTS_JSON = os.path.join(script_dir, 'machine_learning', 'results.json')

# --- Simplified Cache ---
SCAN_CACHE_FILE = os.path.join(script_dir, 'scan_cache.json')

# ClamAV base folder path
clamav_folder = os.path.join(script_dir, "ClamAV")
libclamav_path = os.path.join(clamav_folder, "libclamav.dll")
clamav_database_directory_path = os.path.join(clamav_folder, "database")

detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")

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
# Global cache for scan results: md5 -> {'threat_name': str, 'is_unknown': bool}
scan_cache: Dict[str, Dict[str, Any]] = {}

# ---------------- Utility functions ----------------
def compute_md5(path: str) -> str:
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError) as e:
        logger.error(f"Could not compute MD5 for {path}: {e}")
        return ""

def load_scan_cache():
    """Load the scan cache file."""
    global scan_cache
    if not os.path.exists(SCAN_CACHE_FILE):
        scan_cache = {}
        return
    try:
        with open(SCAN_CACHE_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                scan_cache = {}
                return
            scan_cache = json.loads(content)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Cache file {SCAN_CACHE_FILE} is corrupted or unreadable: {e}. Starting fresh.")
        try:
            os.remove(SCAN_CACHE_FILE)
        except OSError:
            pass
        scan_cache = {}

def save_scan_cache():
    """Save the scan cache file."""
    try:
        with open(SCAN_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(scan_cache, f, indent=4)
    except IOError as e:
        logger.error(f"Could not save cache file {SCAN_CACHE_FILE}: {e}")

# ---------------- YARA preload ----------------
def preload_yara_rules(rules_dir: str):
    global _global_yara_compiled
    for rule_filename in ORDERED_YARA_FILES:
        rule_filepath = os.path.join(rules_dir, rule_filename)
        if not os.path.exists(rule_filepath):
            logger.info(f"YARA rule not found (skipping): {rule_filepath}")
            continue
        try:
            if rule_filename == 'yaraxtr.yrc':
                # pass file object to deserialize_from
                with open(rule_filepath, "rb") as f:
                    rules = yara_x.Rules.deserialize_from(f)
                    _global_yara_compiled[rule_filename] = rules
            else:
                # works for precompiled YARA rules
                compiled = yara.load(rule_filepath)
                _global_yara_compiled[rule_filename] = compiled
            logger.info(f"Preloaded YARA rules: {rule_filename}")
        except Exception as e:
            logger.error(f"Failed to preload YARA rule {rule_filename}: {e}")

def reload_clamav_database():
    """
    Reloads the ClamAV engine with the updated database.
    Required after updating signatures.
    """
    try:
        logger.info("Reloading ClamAV database...")
        clamav_scanner.loadDB()
        logger.info("ClamAV database reloaded successfully.")
    except Exception as ex:
        logger.error(f"Failed to reload ClamAV database: {ex}")

def scan_file_with_clamav(file_path):
    """Scan file using the in-process ClamAV wrapper (scanner) and return virus name or 'Clean'."""
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
    Runs native Detect It Easy (DIE) on the given file and returns the DIE output (plain text).
    Optimized version that doesn't save results to disk.
    """
    try:
        # Run native DIE scan
        result = die.scan_file(file_path, die.ScanFlags.RESULT_AS_JSON)
        
        # Format output to match original plain text format
        if not result or 'detects' not in result:
            stdout_output = "Binary\n    Unknown: Unknown"
        else:
            output_lines = ["Binary"]
            for detect in result['detects']:
                if 'values' in detect:
                    for value in detect['values']:
                        name = value.get('name', 'Unknown')
                        version = value.get('version', '')
                        type_info = value.get('type', '')
                        info = value.get('info', '')
                        
                        if version:
                            line = f"    {type_info}: {name}({version})"
                        else:
                            line = f"    {type_info}: {name}"
                        
                        if info:
                            line += f"[{info}]"
                        
                        output_lines.append(line)
            
            if len(output_lines) == 1:
                output_lines.append("    Unknown: Unknown")
            
            stdout_output = "\n".join(output_lines)

        return stdout_output

    except Exception as ex:
        logger.error(f"DIE analysis error for {file_path}: {ex}")
        return None

def get_die_output_binary(path: str) -> Optional[str]:
    """
    Returns die_output for a non plain text file.
    (Assumes the file isn't plain text, so always calls analyze_file_with_die())
    """
    die_output = analyze_file_with_die(path)
    return die_output

def get_die_output(path: str) -> Tuple[str, bool]:
    """
    Returns (die_output, plain_text_flag) without in-memory caching.
    Uses get_die_output_binary() if the file is not plain text.
    """
    try:
        with open(path, "rb") as f:
            peek = f.read(8192)
    except IOError:
        return "Error: Could not read file", False

    if is_plain_text(peek):
        die_output = "Binary\n    Format: plain text"
        plain_text_flag = True
    else:
        die_output = get_die_output_binary(path)
        plain_text_flag = False

    if die_output is None: # handle case where analyze_file_with_die fails
        die_output = "Error: DIE analysis failed"

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
        logger.info("DIE output indicates an unknown file (ignoring extra errors).")
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

def calculate_similarity(features1: dict, features2: dict) -> float:
    """
    Calculate similarity between two feature dictionaries.
    Similarity = (# of matching keys with equal values) / max(len(features1), len(features2))
    Returns a value between 0 and 1.
    """
    if not features1 or not features2:
        return 0.0

    # Find keys that exist in both dicts
    common_keys = set(features1.keys()) & set(features2.keys())

    # Count keys where values are exactly equal
    matching_keys = sum(1 for key in common_keys if features1[key] == features2[key])

    # Normalize by the size of the larger dict
    similarity = matching_keys / max(len(features1), len(features2))

    return similarity

def scan_file_with_machine_learning_ai(file_path, threshold=0.86):
    """Scan a file for malicious activity using machine learning definitions loaded from JSON."""
    malware_definition = "Unknown"
    try:
        pe = pefile.PE(file_path)
        pe.close()
    except pefile.PEFormatError:
        return False, malware_definition, 0

    # Extract features directly, no caching
    file_numeric_features = pe_extractor.extract_numeric_features(file_path)
    if not file_numeric_features:
        return False, "Feature-Extraction-Failed", 0

    is_malicious_ml = False
    nearest_malicious_similarity = 0
    nearest_benign_similarity = 0

    # Check malicious definitions
    for ml_feats, info in zip(malicious_numeric_features, malicious_file_names):
        similarity = calculate_similarity(file_numeric_features, ml_feats)
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
            similarity = calculate_similarity(file_numeric_features, ml_feats)
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
            logger.info(f"File {file_path} is classified as unknown with similarity: {nearest_benign_similarity}")

    # Return result
    if is_malicious_ml:
        return True, malware_definition, nearest_malicious_similarity
    else:
        return False, malware_definition, nearest_benign_similarity

def scan_file_ml(
    file_path: str,
    *,
    pe_file: bool = False,
    signature_check: Optional[Dict[str, Any]] = None,
    benign_threshold: float = 0.93,
) -> Tuple[bool, str, float, list]:
    """
    Perform ML-only scan and return simplified result.
    Returns (malware_found, virus_name, benign_score)
    """
    try:
        if not pe_file:
            logger.debug("ML scan skipped: not a PE file: %s", os.path.basename(file_path))
            return False, "Clean", 0.0, []

        # Unpack all 4 values
        is_malicious_ml, malware_definition, benign_score = scan_file_with_machine_learning_ai(file_path)

        sig_valid = bool(signature_check and signature_check.get("is_valid", False))

        if is_malicious_ml:
            if benign_score is None:
                benign_score = 0.0
            # Decide malware vs benign using threshold
            if benign_score < benign_threshold:
                # ML -> malware
                if sig_valid and isinstance(malware_definition, str):
                    malware_definition = f"{malware_definition}.SIG"
                logger.critical(
                    "Infected file detected (ML): %s - Virus: %s",
                    os.path.basename(file_path),
                    malware_definition,
                )
                return True, malware_definition, benign_score
            else:
                logger.info(
                    "File marked benign by ML (score=%s): %s",
                    benign_score,
                    os.path.basename(file_path),
                )
                return False, "Benign", benign_score
        else:
            logger.info("No malware detected by ML: %s", os.path.basename(file_path))
            return False, "Clean", benign_score

    except Exception as ex:
        err_msg = f"ML scan error: {ex}"
        logger.error(err_msg)
        return False, "Clean", 0.0, []

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
def log_scan_result(file_path: str, md5: str, threat_name: str, yara_rules: list = None):
    """Minimal logging - only log threats, not clean files.
       Uses MD5 or basename instead of full file path."""
    if threat_name != "Clean":
        logger.warning(f"THREAT: {md5} | {threat_name}")

        # Only log YARA FP if needed
        if yara_rules:
            fp_log_path = "yara_falsepositives.log"
            try:
                with open(fp_log_path, "a", encoding="utf-8") as fp_log:
                    fp_log.write(
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} | "
                        f"{md5} | {', '.join(yara_rules)}\n"
                    )
            except Exception as e:
                logger.error(f"Could not write YARA FP log: {e}")

# ---------------- Per-file Processing ----------------
def scan_file_worker(file_to_scan: str) -> tuple:
    """
    Worker function that scans a single file, using a cache.
    Returns essential info: (file_path, threat_name, md5, yara_rules, is_unknown)
    """
    try:
        # --- Initial check and MD5 calculation ---
        if not os.path.exists(file_to_scan) or os.path.getsize(file_to_scan) == 0:
            return (file_to_scan, "Error: File not found or empty", None, [], False)

        md5_hash = compute_md5(file_to_scan)
        if not md5_hash:
            return (file_to_scan, "Error: Could not compute MD5", None, [], False)

        # --- Check cache first ---
        with thread_lock:
            cached_result = scan_cache.get(md5_hash)
        
        if cached_result is not None and isinstance(cached_result, dict):
            # Result is cached, skip full scan
            return (
                file_to_scan,
                cached_result.get('threat_name', 'Error'),
                md5_hash,
                [],  # no yara matches from cache
                cached_result.get('is_unknown', False)
            )

        # --- If not cached, perform the full scan ---
        threat_name = "Clean"  # Default result
        yara_matches = []
        is_unknown = False  # Default
        
        # --- Check if file is fully unknown by DIE ---
        die_output, _ = get_die_output(file_to_scan)
        if is_file_fully_unknown(die_output):
            logger.info(f"Skipping scan for fully unknown file: {os.path.basename(file_to_scan)}")
            threat_name = "Clean"  # Treat as clean and cache it
            is_unknown = True
        else:
            # Add retry logic for the actual scanning part
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # --- SCANNING PIPELINE ---
                    clamav_virus_name = scan_file_with_clamav(file_to_scan)

                    if clamav_virus_name not in ["Clean", "Error"]:
                        threat_name = clamav_virus_name
                    else:
                        # Only run ML/YARA if ClamAV is clean
                        malware_found, virus_name, benign_score = scan_file_ml(
                            file_to_scan,
                            pe_file=True,
                            signature_check=None,
                            benign_threshold=0.93
                        )

                        if malware_found:
                            threat_name = virus_name
                        elif virus_name == "Benign":
                            threat_name = "Clean"  # ML white-listed / benign
                        else:
                            # ML gave no opinion or error -> fallback to YARA
                            yara_matches = scan_file_with_yara_sequentially(file_to_scan, excluded_yara_rules)
                            if yara_matches:
                                threat_name = yara_matches[0]
                            else:
                                # If ML explicitly said "Unknown", preserve it
                                if virus_name == "Unknown":
                                    threat_name = "Unknown"
                                else:
                                    threat_name = "Clean"
                    
                    # If scan was successful, break the retry loop
                    break
                    
                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"Scan attempt {attempt + 1} failed for {file_to_scan}: {e}. Retrying...")
                        time.sleep(0.1)  # Brief pause before retry
                    else:
                        logger.error(f"All {max_retries} scan attempts failed for {file_to_scan}: {e}")
                        threat_name = "Error: Scan failed after retries"
                    
        # --- Update cache with the new result ---
        # Do not cache errors
        if not threat_name.startswith("Error"):
            with thread_lock:
                scan_cache[md5_hash] = {
                    'threat_name': threat_name,
                    'is_unknown': is_unknown
                }
        
        return (file_to_scan, threat_name, md5_hash, yara_matches, is_unknown)

    except Exception as e:
        # Catch errors from initial MD5 calculation or other setup issues
        logger.error(f"Unhandled error in worker for {file_to_scan}: {e}")
        return (file_to_scan, "Error: Unhandled worker error", None, [], False)

# ---------------- Real-time JSON writer ----------------
class RealTimeJSONWriter:
    """Writes JSON results in real-time without storing in memory.
       Stores only hash and threat info, no file paths.
       Skips error entries entirely.
    """

    def __init__(self, output_file: str):
        self.output_file = output_file
        self.file_handle = None
        self.first_entry = True

    def __enter__(self):
        self.file_handle = open(self.output_file, "w", encoding="utf-8")
        self.file_handle.write("[\n")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file_handle:
            self.file_handle.write("\n]\n")
            self.file_handle.close()

    def write_result(self, file_path: str, threat_name: str, md5: str, is_unknown: bool):
        """Write single result immediately. Avoid logging file paths and skip errors."""
        # Skip errors completely
        if threat_name.startswith("Error"):
            return

        if not self.first_entry:
            self.file_handle.write(",\n")

        result = {
            'id': md5,  # unique identifier (hash only)
            'is_threat': threat_name != "Clean",
            'threat_name': threat_name,
            'is_unknown': is_unknown
        }

        json.dump(result, self.file_handle, ensure_ascii=False)
        self.file_handle.flush()  # Ensure immediate write
        self.first_entry = False

def main():
    global excluded_yara_rules, clamav_scanner
    
    parser = argparse.ArgumentParser(description="HydraDragon Antivirus with real-time logging.")
    parser.add_argument("path", help="Path to file or directory to scan.")
    parser.add_argument("--output", default="scan_results.json", help="Output JSON file for results.")
    args = parser.parse_args()
    
    target = args.path
    if not os.path.exists(target):
        logger.critical(f"Target not found: {target}")
        sys.exit(6)

    # --- Load existing cache ---
    logger.info("Loading scan result cache...")
    load_scan_cache()
    
    # --- ONE-TIME INITIALIZATION (PARALLEL LOADING) ---
    logger.info("Loading antivirus components...")
    init_start = time.perf_counter()
    
    with ThreadPoolExecutor(max_workers=1000) as init_executor:
        # Submit all initialization tasks in parallel
        yara_future = init_executor.submit(preload_yara_rules, YARA_RULES_DIR)
        excluded_future = init_executor.submit(load_excluded_rules, EXCLUDED_RULES_FILE)
        ml_future = init_executor.submit(load_ml_definitions, ML_RESULTS_JSON)
        clamav_future = init_executor.submit(lambda: clamav.Scanner(
            libclamav_path=libclamav_path, 
            dbpath=clamav_database_directory_path
        ))
        
        # Wait for all components to load
        try:
            yara_future.result()  # preload_yara_rules already handles global state
            excluded_yara_rules = set(excluded_future.result())
            ml_future.result()  # load_ml_definitions handles global state
            clamav_scanner = clamav_future.result()
            
            logger.info(f"All components loaded in {time.perf_counter() - init_start:.2f}s")
            
        except Exception as e:
            logger.critical(f"Failed to initialize antivirus components: {e}")
            sys.exit(1)
    
    # --- FILE DISCOVERY ---
    all_files = []
    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for fname in files:
                all_files.append(os.path.join(root, fname))
    else:
        all_files = [target]
    
    total_files = len(all_files)
    logger.info(f"Starting scan of {total_files} files...")
    
    # --- SCANNING WITH REAL-TIME WRITING ---
    start_wall = time.perf_counter()
    threats_found = 0
    
    with RealTimeJSONWriter(args.output) as json_writer:
        with ThreadPoolExecutor(max_workers=100) as executor:  # Reduced workers
            # Submit all tasks
            futures = {executor.submit(scan_file_worker, f): f for f in all_files}
            
            # Process results with tqdm
            with tqdm(total=total_files, desc="Scanning", unit="files") as pbar:
                for fut in as_completed(futures):
                    try:
                        file_path, threat_name, md5_hash, yara_rules, is_unknown = fut.result()
                        
                        # Write result immediately
                        if md5_hash:
                            json_writer.write_result(file_path, threat_name, md5_hash, is_unknown)
                        
                        # Log anything that is not Clean and not an Error
                        if threat_name not in ("Clean", "Unknown") and not threat_name.startswith("Error"):
                            log_scan_result(file_path, md5_hash, threat_name, yara_rules)
                            threats_found += 1
                        
                        pbar.update(1)
                        
                    except Exception as e:
                        logger.error(f"Error processing result for {futures[fut]}: {e}")
                        pbar.update(1)
    
    elapsed = time.perf_counter() - start_wall
    logger.info(f"Scan completed in {elapsed:.2f}s. {threats_found} threats found. Results: {args.output}")

    # --- Save updated cache ---
    logger.info("Saving scan result cache...")
    save_scan_cache()

if __name__ == "__main__":
    main()
