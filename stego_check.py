import sys
import os
import subprocess
from typing import List, Optional, Tuple, Dict, Any, Union, Set
from pathlib import Path
import exifread
from PIL import Image
import shutil
import base64
import binascii
import json
from datetime import datetime
import io
import math
import re
import time
import logging
from contextlib import contextmanager
from collections import Counter
import traceback

###############################################################################
# Logging setup
###############################################################################

class ProgressFormatter(logging.Formatter):
    """Custom formatter that includes timing and progress information."""
    
    def __init__(self):
        super().__init__('%(asctime)s - %(levelname)s - %(message)s')
        self.start_time = time.time()
        
    def format(self, record):
        # Add elapsed time to the record
        elapsed = time.time() - self.start_time
        record.elapsed = f"{elapsed:.2f}s"
        
        # Add indentation based on the stack depth (for hierarchical display)
        stack_depth = len(logging.getLogger().handlers)
        record.indent = "  " * (stack_depth - 1) if stack_depth > 1 else ""
        
        # Format with timing for INFO level and above
        if record.levelno >= logging.INFO:
            record.msg = f"[{record.elapsed}] {record.indent}{record.msg}"
        else:
            record.msg = f"{record.indent}{record.msg}"
        
        return super().format(record)

def setup_logging(output_dir: Optional[Path] = None) -> None:
    """
    Set up logging configuration.
    
    Args:
        output_dir: Directory to save log files. If None, uses current directory.
    """
    # Create formatter
    formatter = ProgressFormatter()
    
    # Console handler (INFO and above)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # File handler (DEBUG and above)
    if output_dir is None:
        output_dir = Path("stego_check_results")
        output_dir.mkdir(exist_ok=True)
    
    log_file = output_dir / "analysis.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    
    logging.info(f"Analysis started at {datetime.now().isoformat()}")
    logging.info(f"Log file: {log_file}")

@contextmanager
def log_operation(operation: str, level: int = logging.INFO) -> None:
    """
    Context manager for logging operations with timing.
    
    Args:
        operation: Description of the operation
        level: Logging level to use
    """
    start_time = time.time()
    logging.log(level, f"Starting {operation}...")
    try:
        yield
        elapsed = time.time() - start_time
        logging.log(level, f"Completed {operation} in {elapsed:.2f}s")
    except Exception as e:
        elapsed = time.time() - start_time
        logging.error(f"Error in {operation} after {elapsed:.2f}s: {e}")
        raise

def log_progress(current: int, total: int, operation: str) -> None:
    """
    Log progress of an operation.
    
    Args:
        current: Current item number
        total: Total number of items
        operation: Description of the operation
    """
    percentage = (current / total) * 100
    logging.info(f"Progress: {current}/{total} {operation} ({percentage:.1f}%)")

###############################################################################
# Known pattern sets
###############################################################################

TARGET_STRINGS = [
    "4NBT",   # exact
    "4nbt",   # case-insensitive
    "TBN4",   # reversed
    "tbn4",   # reversed + case-insensitive
]

# Base64 versions of "4NBT" => "NE5CVA==" (with variations)
BASE64_VARIANTS = [
    "NE5CVA",
    "NE5CVA=",
    "NE5CVA==",
    "ne5cva",
    "ne5cva=",
    "ne5cva==",
]

# Binary variants of "4NBT", "TBN4", etc. (ASCII -> binary)
BINARY_VARIANTS = [
    "00110100010011100100001001010100", # "4NBT"
    "01010100010000100100111000110100", # "TBN4"
    "00110100001101110110001001110100", # "4nbt"
    "01110100001100100110111000110100", # "tbn4"
]

# ZIP file signatures and markers
ZIP_SIGNATURES = {
    'local_file_header': b'PK\x03\x04',  # Start of file
    'central_directory': b'PK\x01\x02',  # Central directory
    'end_of_central_dir': b'PK\x05\x06',  # End of central directory
    'spanned_marker': b'PK\x07\x08',     # Spanned marker
}

###############################################################################
# Result handling and organization
###############################################################################

class StegResults:
    """
    Class to store and manage steganography analysis results.
    """
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: Dict[str, List[str]] = {
            "metadata": [],
            "raw_bytes": [],
            "binary_patterns": [],
            "lsb": [],
            "channels": [],
            "binwalk": [],
            "icc_profile": [],
            "zip_signatures": [],
            "appended_data": [],
            "histogram": [],
            "jpeg_comments": [],
            "large_metadata": []
        }
        self.has_findings = False
        self.analysis_time = datetime.now()
        
    def add_finding(self, category: str, finding: str) -> None:
        """
        Add a finding to the specified category.
        
        Args:
            category: The category to add the finding to
            finding: The finding to add
        """
        if category not in self.findings:
            self.findings[category] = []
        self.findings[category].append(finding)
        self.has_findings = True

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert results to a dictionary format.
        
        Returns:
            Dict containing the analysis results
        """
        return {
            "file_name": self.file_path.name,
            "file_path": str(self.file_path),
            "file_size": self.file_path.stat().st_size,
            "analysis_time": self.analysis_time.isoformat(),
            "findings": self.findings,
            "has_findings": self.has_findings,
            "summary": {
                "total_findings": sum(len(findings) for findings in self.findings.values()),
                "findings_by_category": {
                    category: len(findings) 
                    for category, findings in self.findings.items()
                }
            }
        }

class ResultWriter:
    """
    Handles writing analysis results to files and console.
    """
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.summary_findings: List[Dict[str, Any]] = []
        # Track consolidated findings across all files
        self.consolidated_findings: Dict[str, Dict[str, Set[Tuple[str, str]]]] = {
            "metadata": {},
            "raw_bytes": {},
            "binary_patterns": {},
            "lsb": {},
            "channels": {},
            "binwalk": {},
            "icc_profile": {},
            "zip_signatures": {},
            "appended_data": {},
            "histogram": {},
            "jpeg_comments": {},
            "large_metadata": {}
        }

    def write_file_results(self, results: StegResults) -> Path:
        """
        Write individual file results and return the result directory path.
        
        Args:
            results: The StegResults object containing the analysis results
            
        Returns:
            Path to the directory containing the results
        """
        # Create directory for this file's results
        result_dir = self.output_dir / results.file_path.stem
        result_dir.mkdir(parents=True, exist_ok=True)

        # Write detailed results
        with open(result_dir / "analysis.json", "w") as f:
            json.dump(results.to_dict(), f, indent=4)

        # Write human-readable summary
        with open(result_dir / "summary.txt", "w") as f:
            f.write(f"Analysis Results for: {results.file_path.name}\n")
            f.write(f"Analysis Time: {results.analysis_time.isoformat()}\n")
            f.write(f"File Size: {results.file_path.stat().st_size:,} bytes\n\n")
            
            # Write findings by category
            for category, findings in results.findings.items():
                if findings:
                    f.write(f"{category.upper()} Findings:\n")
                    for finding in findings:
                        f.write(f"  - {finding}\n")
                    f.write("\n")
            
            # Write summary statistics
            f.write("\nSUMMARY STATISTICS\n")
            f.write("=================\n")
            total_findings = sum(len(findings) for findings in results.findings.values())
            f.write(f"Total findings: {total_findings}\n")
            for category, findings in results.findings.items():
                if findings:
                    f.write(f"{category}: {len(findings)} finding(s)\n")

        # Store for final summary
        if results.has_findings:
            self.summary_findings.append(results.to_dict())
            # Add to consolidated findings
            for category, findings in results.findings.items():
                for finding in findings:
                    # Skip error messages and empty findings
                    if "Error during analysis:" in finding or not finding.strip():
                        continue
                    # Initialize dict for this finding if not exists
                    if finding not in self.consolidated_findings[category]:
                        self.consolidated_findings[category][finding] = set()
                    # Add tuple of (filename, finding)
                    self.consolidated_findings[category][finding].add((results.file_path.name, finding))

        return result_dir

    def write_final_summary(self) -> None:
        """Write a final summary of all analyses."""
        print("\nWriting final summary...")
        
        with open(self.output_dir / "final_summary.txt", "w") as f:
            f.write("STEGO ANALYSIS FINAL SUMMARY\n")
            f.write("===========================\n\n")
            f.write(f"Analysis completed at: {datetime.now().isoformat()}\n")
            f.write(f"Total files analyzed: {len(self.summary_findings)}\n\n")

            # Write per-file summary
            f.write("PER-FILE FINDINGS\n")
            f.write("================\n\n")
            
            if not self.summary_findings:
                f.write("No findings in any files.\n\n")
            else:
                for result in self.summary_findings:
                    f.write(f"File: {result['file_name']}\n")
                    f.write(f"Size: {result['file_size']:,} bytes\n")
                    has_findings = False
                    for category, findings in result['findings'].items():
                        if findings:
                            has_findings = True
                            f.write(f"  {category.upper()}:\n")
                            for finding in findings[:5]:  # Show first 5 findings
                                f.write(f"    - {finding}\n")
                            if len(findings) > 5:
                                f.write(f"    ... and {len(findings) - 5} more findings\n")
                    if not has_findings:
                        f.write("  No findings\n")
                    f.write("\n")

            # Write consolidated findings
            f.write("\nCONSOLIDATED FINDINGS ACROSS ALL FILES\n")
            f.write("===================================\n\n")
            
            total_interesting_findings = 0
            has_consolidated_findings = False
            
            for category, findings_dict in self.consolidated_findings.items():
                if findings_dict:
                    interesting_findings = {
                        finding: files for finding, files in findings_dict.items()
                        if any(
                            pattern.lower() in finding.lower() 
                            for pattern in TARGET_STRINGS + BASE64_VARIANTS + BINARY_VARIANTS
                        ) or "suspicious" in finding.lower() or "[!]" in finding
                    }
                    if interesting_findings:
                        has_consolidated_findings = True
                        total_interesting_findings += len(interesting_findings)
                        f.write(f"{category.upper()} Interesting Patterns:\n")
                        for finding, files in interesting_findings.items():
                            file_list = sorted(set(file for file, _ in files))
                            f.write(f"  - {finding}\n")
                            f.write(f"    Found in {len(file_list)} files: {', '.join(file_list)}\n")
                        f.write("\n")
            
            if not has_consolidated_findings:
                f.write("No interesting patterns found across files.\n\n")
            else:
                f.write(f"\nTotal interesting patterns found: {total_interesting_findings}\n\n")

            # Write statistics
            f.write("\nSTATISTICS\n")
            f.write("==========\n")
            files_with_findings = sum(1 for result in self.summary_findings if result['has_findings'])
            f.write(f"Files with findings: {files_with_findings} out of {len(self.summary_findings)}\n")
            
            has_category_findings = False
            for category in self.consolidated_findings:
                total_patterns = sum(len(files) for files in self.consolidated_findings[category].values())
                if total_patterns:
                    has_category_findings = True
                    f.write(f"{category.upper()}: {total_patterns} total findings\n")
            
            if not has_category_findings:
                f.write("No findings in any category\n")
            
            print(f"Final summary written to: {self.output_dir / 'final_summary.txt'}")

class OutputCapture:
    """Context manager to capture print output."""
    def __init__(self):
        self.captured_output: List[str] = []
        self._original_stdout = sys.stdout
        self._string_io = io.StringIO()

    def __enter__(self):
        sys.stdout = self._string_io
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = self._original_stdout
        self.captured_output = self._string_io.getvalue().splitlines()
        self._string_io.close()

###############################################################################
# Utility: Detect suspicious-encoded strings
###############################################################################

def check_file_signatures(data: bytes) -> None:
    """
    Check binary data for common file signatures.
    
    Args:
        data: Binary data to check
    """
    signatures = {
        'ZIP': b'PK\x03\x04',
        'GZIP': b'\x1f\x8b\x08',
        'PNG': b'\x89PNG',
        'JPEG': b'\xff\xd8\xff',
        'PDF': b'%PDF',
        'RAR': b'Rar!\x1a\x07',
        '7Z': b'7z\xbc\xaf\x27\x1c',
        'BZIP2': b'BZh',
        'ZLIB': b'\x78\x9c',
        'ZLIB_BEST': b'\x78\xda'
    }
    
    for sig_type, sig in signatures.items():
        # Check at start
        if data.startswith(sig):
            logging.warning(f"Found {sig_type} signature at start of data")
        
        # Check for signature anywhere in data
        offset = data.find(sig)
        if offset > 0:
            logging.warning(f"Found {sig_type} signature at offset {offset}")

def find_suspicious_strings(text: str) -> List[str]:
    """
    Find suspicious strings that might indicate hidden data.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of suspicious strings found
    """
    suspicious = []
    
    # Common steganography tool strings
    stego_tools = [
        'steghide', 'outguess', 'jsteg', 'jphide', 'jpseek',
        'stegdetect', 'stegbreak', 'stegano', 'openstego',
        'stegosuite', 'stegextract', 'stegsnow', 'f5'
    ]
    
    # Check for tool names
    for tool in stego_tools:
        if tool.lower() in text.lower():
            suspicious.append(f"Steganography tool reference: {tool}")
    
    # Check for base64-like patterns
    if looks_like_base64(text):
        suspicious.append("Base64-like encoded data")
    
    # Check for hex dumps
    hex_pattern = re.compile(r'([0-9a-fA-F]{2}[\s:]){8,}')
    if hex_pattern.search(text):
        suspicious.append("Hex dump pattern")
    
    # Check for password hints
    password_hints = ['password', 'passwd', 'pass:', 'key:', 'secret']
    for hint in password_hints:
        if hint.lower() in text.lower():
            suspicious.append(f"Password hint: {hint}")
    
    return suspicious

def calculate_entropy(data: Union[bytes, str]) -> float:
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: Data to analyze (bytes or string)
        
    Returns:
        Entropy value between 0 and 8
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')
    
    # Count byte frequencies
    freq = Counter(data)
    length = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def looks_like_base64(text: str) -> bool:
    """
    Check if a string looks like base64 encoded data.
    
    Args:
        text: String to check
        
    Returns:
        True if string appears to be base64 encoded
    """
    # Must be at least 20 chars
    if len(text) < 20:
        return False
    
    # Must be multiple of 4 (with padding)
    if len(text.rstrip('=')) % 4 != 0:
        return False
    
    # Must only contain valid base64 chars
    base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    return all(c in base64_chars for c in text)

###############################################################################
# 1) Metadata scanning
###############################################################################

def check_metadata(file_path: Path) -> None:
    """
    Check image metadata for occurrences of "4NBT" or variants,
    plus suspicious encoded strings.
    
    Args:
        file_path: Path to the image file
    """
    logging.info("Checking metadata...")
    
    with log_operation("Reading EXIF data", level=logging.DEBUG):
        with open(file_path, 'rb') as f:
            tags: Dict[str, Any] = exifread.process_file(f)
        
        if not tags:
            logging.info("No EXIF metadata found")
            return
        
        logging.debug(f"Found {len(tags)} EXIF tags")
    
    with log_operation("Analyzing metadata content", level=logging.DEBUG):
        findings = 0
        for tag in tags:
            val = str(tags[tag])
            lower_val = val.lower()
            
            # Known patterns
            for tstr in TARGET_STRINGS:
                if tstr.lower() in lower_val:
                    findings += 1
                    logging.warning(f"Found '{tstr}' in metadata tag [{tag}] = {val}")
                    
            for b64str in BASE64_VARIANTS:
                if b64str.lower() in lower_val:
                    findings += 1
                    logging.warning(f"Found base64-like '{b64str}' in metadata tag [{tag}] = {val}")
            
            # Search suspicious strings
            suspects = find_suspicious_strings(lower_val)
            for s in suspects:
                findings += 1
                logging.warning(f"Suspicious string in metadata tag [{tag}]: {s}")
        
        if findings:
            logging.info(f"Found {findings} suspicious patterns in metadata")
        else:
            logging.info("No suspicious patterns found in metadata")

###############################################################################
# 2) Raw byte scanning
###############################################################################

def check_raw_bytes(file_path: Path) -> None:
    """
    Search for 4NBT and also look for suspicious ASCII or hex in the raw byte content.
    
    Args:
        file_path: Path to the image file
    """
    logging.info("Checking raw bytes...")
    
    with log_operation("Reading file content", level=logging.DEBUG):
        with open(file_path, 'rb') as f:
            data = f.read()
        logging.debug(f"Read {len(data):,} bytes")
    
    findings = 0
    with log_operation("Analyzing ASCII content", level=logging.DEBUG):
        # ASCII analysis
        ascii_data = data.decode('latin-1', errors='ignore')
        lower_ascii = ascii_data.lower()
        
        # Known patterns
        for tstr in TARGET_STRINGS:
            if tstr.lower() in lower_ascii:
                findings += 1
                logging.warning(f"Found '{tstr}' in raw ASCII data!")
    
    with log_operation("Analyzing hex content", level=logging.DEBUG):
        # Hex analysis
        hex_string = data.hex()
        if "344e4254" in hex_string:
            findings += 1
            logging.warning("Found hex pattern '34 4E 42 54' (4NBT)!")
        if "54424e34" in hex_string:
            findings += 1
            logging.warning("Found reversed hex pattern '54 42 4E 34' (TBN4)!")
    
    with log_operation("Checking base64 variants", level=logging.DEBUG):
        for b64str in BASE64_VARIANTS:
            if b64str.lower() in lower_ascii:
                findings += 1
                logging.warning(f"Found base64-like '{b64str}' in raw ASCII data!")
    
    with log_operation("Analyzing suspicious patterns", level=logging.DEBUG):
        # Suspicious-encoded substrings
        suspects = find_suspicious_strings(ascii_data)
        for s in suspects:
            findings += 1
            logging.warning(f"Suspicious substring in raw data: {s}")
    
    if findings:
        logging.info(f"Found {findings} suspicious patterns in raw bytes")
    else:
        logging.info("No suspicious patterns found in raw bytes")

###############################################################################
# 3) Advanced binary pattern checks
###############################################################################

def check_binary_patterns(file_path: Path) -> None:
    """
    Search for direct binary patterns (and reversed/UTF-16) for "4NBT" or variants.
    """
    print("[*] Checking binary patterns...")
    with open(file_path, 'rb') as f:
        data = f.read()

    # Direct binary
    bin_str = ''.join(format(byte, '08b') for byte in data)
    # Reversed data
    reversed_data = bytes(reversed(data))
    rev_bin_str = ''.join(format(byte, '08b') for byte in reversed_data)

    # Check patterns in direct binary
    for pattern in BINARY_VARIANTS:
        if pattern in bin_str:
            print(f"    Found pattern in direct binary: {pattern}")
    # Check patterns in reversed binary
    for pattern in BINARY_VARIANTS:
        if pattern in rev_bin_str:
            print(f"    Found pattern in reversed binary: {pattern}")

    # UTF-16 approach
    try:
        utf16_data = data.decode('utf-16', errors='ignore')
        utf16_bin = ''.join(format(ord(c), '016b') for c in utf16_data)
        for pattern in BINARY_VARIANTS:
            if pattern in utf16_bin:
                print(f"    Found pattern in UTF-16 binary: {pattern}")
    except UnicodeError:
        pass

###############################################################################
# 4) Multi-bit LSB extraction
###############################################################################

def extract_lsb(img: Image.Image, bits: int) -> str:
    """
    Extract stego data using the least 'bits' bits of each channel in the given image.
    Return a 'latin-1' decoded string.
    """
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    pixels = list(img.getdata())
    bit_stream = []
    for px in pixels:
        # px might be (R, G, B) or (R, G, B, A)
        for channel in px[:3]:  # ignore alpha
            # Get 'bits' LSB
            for i in range(bits):
                bit_stream.append((channel >> i) & 1)
    # Convert bits -> bytes -> string
    bytes_out = bytearray()
    for i in range(0, len(bit_stream), 8):
        chunk = bit_stream[i:i+8]
        if len(chunk) < 8:
            break
        val = 0
        for idx, bit in enumerate(chunk):
            val |= (bit << idx)
        bytes_out.append(val)
    return bytes_out.decode('latin-1', errors='ignore')

def check_multibit_lsb(file_path: Path) -> None:
    """
    Attempt 1-bit, 2-bit, and 4-bit LSB extraction to see if known patterns appear,
    AND also look for suspicious encoded strings in the extracted text.
    """
    print("[*] Checking multi-bit LSB steganography (1, 2, and 4 bits)...")
    try:
        img = Image.open(file_path)
    except Exception as e:
        print(f"    Could not open image for LSB analysis: {e}")
        return

    for b in [1, 2, 4]:
        print(f"    Extracting {b}-bit LSB data...")
        extracted_str = extract_lsb(img, b)
        lower_extracted = extracted_str.lower()
        found_flag = False
        # Known patterns
        for tstr in TARGET_STRINGS:
            if tstr.lower() in lower_extracted:
                print(f"        Found '{tstr}' in {b}-bit LSB extraction!")
                found_flag = True

        for b64str in BASE64_VARIANTS:
            if b64str.lower() in lower_extracted:
                print(f"        Found base64-like '{b64str}' in {b}-bit LSB extraction!")
                found_flag = True

        # Suspicious strings
        suspects = find_suspicious_strings(extracted_str)
        for s in suspects:
            print(f"        Suspicious substring in {b}-bit LSB extraction: {s}")
            found_flag = True

        if not found_flag:
            print(f"        No '4NBT' or suspicious patterns found in {b}-bit LSB extraction.")

###############################################################################
# 5) Per-channel scanning
###############################################################################

def check_channels(file_path: Path) -> None:
    """
    Analyze individual color channels for hidden data or suspicious-encoded patterns.
    """
    print("[*] Checking channels individually...")
    try:
        img = Image.open(file_path).convert('RGBA')
    except Exception as e:
        print(f"    Could not open image to separate channels: {e}")
        return

    channel_names = ["R", "G", "B", "A"]
    for i, cname in enumerate(channel_names):
        channel = img.split()[i]
        channel_data = channel.tobytes()
        ascii_data = channel_data.decode('latin-1', errors='ignore')
        lower_ascii = ascii_data.lower()

        found_something = False
        # Known patterns
        for tstr in TARGET_STRINGS:
            if tstr.lower() in lower_ascii:
                print(f"    Found '{tstr}' in {cname} channel data!")
                found_something = True

        # check hex
        hex_string = channel_data.hex()
        if "344e4254" in hex_string:
            print(f"    Found '34 4E 42 54' (4NBT) in {cname} channel hex!")
            found_something = True
        if "54424e34" in hex_string:
            print(f"    Found '54 42 4E 34' (TBN4) in {cname} channel hex!")
            found_something = True

        # base64 subsets
        for b64str in BASE64_VARIANTS:
            if b64str.lower() in lower_ascii:
                print(f"    Found base64-like '{b64str}' in {cname} channel data!")
                found_something = True

        # suspicious strings
        suspects = find_suspicious_strings(ascii_data)
        if suspects:
            found_something = True
            for s in suspects:
                print(f"    Suspicious substring in {cname} channel: {s}")

        if not found_something:
            print(f"    No obvious patterns in {cname} channel.")

###############################################################################
# 6) Binwalk scanning
###############################################################################

def check_binwalk(file_path: Path) -> None:
    """
    Use binwalk to check for appended data or hidden files.
    """
    print("[*] Checking for appended/hidden data with binwalk...")
    if not shutil.which("binwalk"):
        print("    binwalk is not installed; skipping.")
        return

    try:
        print("    Running binwalk signature analysis...")
        result = subprocess.run(
            ["binwalk", str(file_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.stdout.strip():
            print("    Binwalk detected:")
            for line in result.stdout.strip().split('\n'):
                print(f"      {line}")
        else:
            print("    No signatures found.")

        # Attempt extraction if something was found
        if "DECIMAL" in result.stdout:
            extract_dir = file_path.parent / ("_binwalk_extract_" + file_path.stem)
            print(f"\n    Attempting extraction to: {extract_dir}")
            extract_result = subprocess.run(
                ["binwalk", "--extract", "--directory", str(extract_dir), str(file_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if extract_result.stdout.strip():
                print("    Extraction output:")
                print(extract_result.stdout)
    except Exception as e:
        print(f"    Binwalk error: {e}")

###############################################################################
# 7) Color-profile / ICC chunk scanning
###############################################################################

def check_icc_profile(file_path: Path) -> None:
    """
    Some images have large ICC profiles or color profiles that can hide data.
    We'll try to extract and scan their content for suspicious patterns.
    """
    print("[*] Checking ICC/color profile data (if present)...")
    try:
        img = Image.open(file_path)
        # Some images might have an info dict with an icc_profile entry
        if hasattr(img, "info") and "icc_profile" in img.info:
            icc_data = img.info["icc_profile"]
            if icc_data:
                # Convert to ASCII set
                ascii_icc = icc_data.decode('latin-1', errors='ignore')
                lower_icc = ascii_icc.lower()

                found_any = False
                for tstr in TARGET_STRINGS:
                    if tstr.lower() in lower_icc:
                        print(f"    Found '{tstr}' in ICC profile!")
                        found_any = True

                for b64str in BASE64_VARIANTS:
                    if b64str.lower() in lower_icc:
                        print(f"    Found base64-like '{b64str}' in ICC profile!")
                        found_any = True

                # suspicious checks
                suspects = find_suspicious_strings(ascii_icc)
                for s in suspects:
                    print(f"    Suspicious substring in ICC profile: {s}")
                    found_any = True

                if not found_any:
                    print("    No obvious data in ICC profile.")
            else:
                print("    ICC profile field is empty.")
        else:
            print("    No ICC profile found in this image.")
    except Exception as e:
        print(f"    Error reading ICC profile: {e}")

###############################################################################
# ZIP Detection
###############################################################################

def check_zip_signatures(file_path: Path) -> None:
    """
    Check for ZIP file signatures and potential ZIP content in the image.
    This includes checking for:
    - Standard ZIP signatures
    - Partial ZIP structures
    - Hidden ZIP data in different parts of the file
    """
    print("[*] Checking for ZIP signatures and content...")
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
        # Track positions of all findings
        findings = []
        
        # 1. Check for standard ZIP signatures
        for sig_name, signature in ZIP_SIGNATURES.items():
            positions = []
            pos = -1
            while True:
                pos = data.find(signature, pos + 1)
                if pos == -1:
                    break
                positions.append(pos)
            
            if positions:
                for pos in positions:
                    findings.append(f"Found {sig_name} signature at offset {pos}")
                    
                    # For local file headers, try to extract filename length and extra field length
                    if sig_name == 'local_file_header' and pos + 30 <= len(data):
                        try:
                            name_length = int.from_bytes(data[pos+26:pos+28], 'little')
                            extra_length = int.from_bytes(data[pos+28:pos+30], 'little')
                            
                            # Try to extract filename if it exists
                            if pos + 30 + name_length <= len(data):
                                filename = data[pos+30:pos+30+name_length].decode('utf-8', errors='ignore')
                                findings.append(f"  Possible filename at offset {pos+30}: {filename}")
                        except Exception:
                            pass
        
        # 2. Look for ZIP-like structures (even if signatures are corrupted)
        # Search for common ZIP metadata markers
        common_extensions = [b'.txt', b'.doc', b'.pdf', b'.jpg', b'.png', b'.zip']
        for ext in common_extensions:
            pos = -1
            while True:
                pos = data.find(ext, pos + 1)
                if pos == -1:
                    break
                # Check if surrounded by printable ASCII (typical for ZIP metadata)
                start = max(0, pos - 20)
                end = min(len(data), pos + len(ext) + 20)
                context = data[start:end].decode('latin-1', errors='ignore')
                if any(c.isprintable() for c in context):
                    findings.append(f"Possible ZIP metadata near offset {pos}: ...{context}...")
        
        # 3. Check for compressed data patterns
        # Look for long sequences of non-printable characters (typical of compressed data)
        non_printable_sequences = []
        sequence_start = None
        min_sequence_length = 50  # Minimum length to consider
        
        for i in range(len(data)):
            byte = data[i]
            is_printable = 32 <= byte <= 126 or byte in (9, 10, 13)  # ASCII printable or whitespace
            
            if not is_printable and sequence_start is None:
                sequence_start = i
            elif is_printable and sequence_start is not None:
                sequence_length = i - sequence_start
                if sequence_length >= min_sequence_length:
                    non_printable_sequences.append((sequence_start, sequence_length))
                sequence_start = None
        
        # Report findings
        if findings:
            print("    ZIP-related findings:")
            for finding in findings:
                print(f"    {finding}")
            
            if non_printable_sequences:
                print("\n    Potential compressed data regions:")
                for start, length in non_printable_sequences:
                    print(f"    Offset {start}: {length} bytes of possible compressed data")
        else:
            print("    No ZIP signatures or related patterns found.")
            
    except Exception as e:
        print(f"    Error during ZIP signature analysis: {e}")

###############################################################################
# 8) Appended Data Check
###############################################################################

def check_appended_data(file_path: Path) -> None:
    """
    Check for data appended after image file format markers.
    Handles multiple EOI markers in JPEGs and corrupted markers.
    
    Args:
        file_path: Path to the image file
    """
    logging.info("Checking for appended data...")
    
    with log_operation("Reading file", level=logging.DEBUG):
        with open(file_path, 'rb') as f:
            data = f.read()
        logging.debug(f"Read {len(data):,} bytes")
    
    findings = 0
    with log_operation("Analyzing file format", level=logging.DEBUG):
        # Check file type
        if data.startswith(b'\x89PNG'):
            # PNG - look for IEND
            iend_pos = data.rfind(b'IEND')
            if iend_pos != -1:
                appended = data[iend_pos+8:]
                if appended:
                    findings += 1
                    logging.warning(f"Found {len(appended)} bytes after PNG IEND chunk")
                    analyze_appended_data(appended)
        
        elif data.startswith(b'\xFF\xD8'):
            # JPEG - find all EOI markers
            positions = []
            i = 0
            while i < len(data) - 1:
                if data[i] == 0xFF and data[i+1] == 0xD9:
                    positions.append(i)
                i += 1
            
            if not positions:
                logging.warning("No EOI markers found in JPEG")
                return
            
            logging.debug(f"Found {len(positions)} EOI markers")
            
            # Check between markers
            for i in range(len(positions)-1):
                between = data[positions[i]+2:positions[i+1]]
                if between:
                    findings += 1
                    logging.warning(f"Found {len(between)} bytes between EOI markers")
                    analyze_appended_data(between)
            
            # Check after last marker
            appended = data[positions[-1]+2:]
            if appended:
                findings += 1
                logging.warning(f"Found {len(appended)} bytes after last EOI marker")
                analyze_appended_data(appended)
    
    if findings:
        logging.info(f"Found {findings} instances of appended data")
    else:
        logging.info("No appended data found")

def analyze_appended_data(data: bytes) -> None:
    """
    Analyze appended data for signatures, entropy, and encoding.
    
    Args:
        data: Bytes to analyze
    """
    with log_operation("Analyzing appended data", level=logging.DEBUG):
        # Check file signatures
        check_file_signatures(data)
        
        # Try text decoding
        try:
            text = data.decode('utf-8', errors='ignore')
            suspects = find_suspicious_strings(text)
            for s in suspects:
                logging.warning(f"Suspicious string in appended data: {s}")
        except UnicodeDecodeError:
            pass
        
        # Check entropy
        entropy = calculate_entropy(data)
        if entropy > 7.5:
            logging.warning(f"High entropy ({entropy:.2f}) in appended data")
        
        # Check for base64
        if looks_like_base64(data.decode('latin-1', errors='ignore')):
            logging.warning("Appended data appears to be base64-encoded")

###############################################################################
# 9) Histogram Analysis
###############################################################################

def check_histogram(file_path: Path) -> None:
    """
    Analyze image histograms for anomalies that might indicate steganography.
    Checks for:
    - Unusual color distribution
    - Low variance in color channels
    - Suspicious patterns in color frequencies
    - LSB anomalies
    
    Args:
        file_path: Path to the image file
    """
    print("[*] Checking histogram for anomalies...")
    try:
        img = Image.open(file_path).convert('RGB')
        pixels = list(img.getdata())
        width, height = img.size
        total_pixels = width * height
        
        # Initialize histogram data
        histograms = {
            'R': [0] * 256,
            'G': [0] * 256,
            'B': [0] * 256
        }
        
        # Build histograms
        for r, g, b in pixels:
            histograms['R'][r] += 1
            histograms['G'][g] += 1
            histograms['B'][b] += 1
            
        # Analyze each channel
        for channel, hist in histograms.items():
            # Calculate basic statistics
            total = sum(hist)
            mean = sum(i * count for i, count in enumerate(hist)) / total
            variance = sum((i - mean) ** 2 * count for i, count in enumerate(hist)) / total
            stddev = math.sqrt(variance)
            
            print(f"    {channel} channel statistics:")
            print(f"      Mean: {mean:.2f}")
            print(f"      StdDev: {stddev:.2f}")
            
            # Check for anomalies
            
            # 1. Very low variance might indicate manipulation
            if stddev < 10:
                print(f"    [!] {channel} channel has unusually low variance!")
                
            # 2. Check for unusual peaks in the histogram
            max_count = max(hist)
            max_index = hist.index(max_count)
            if max_count > total_pixels * 0.5:  # More than 50% of pixels have the same value
                print(f"    [!] {channel} channel has suspicious peak at value {max_index} ({max_count/total_pixels*100:.1f}% of pixels)")
                
            # 3. Check LSB distribution
            lsb_zeros = sum(hist[i] for i in range(0, 256, 2))
            lsb_ones = sum(hist[i] for i in range(1, 256, 2))
            lsb_ratio = lsb_ones / lsb_zeros if lsb_zeros > 0 else float('inf')
            
            if not (0.8 < lsb_ratio < 1.2):  # LSB ratio should be close to 1 in normal images
                print(f"    [!] {channel} channel has suspicious LSB distribution (ratio: {lsb_ratio:.2f})")
                
            # 4. Check for stepwise patterns (common in LSB steganography)
            steps = []
            for i in range(0, 256, 2):
                if abs(hist[i] - hist[i+1]) < total_pixels * 0.001:  # Very similar adjacent values
                    steps.append(i)
            if len(steps) > 50:  # Many stepwise patterns found
                print(f"    [!] {channel} channel shows stepwise patterns typical of LSB steganography")
                
            # 5. Check for empty ranges (unusual in natural images)
            zero_ranges = []
            start = None
            for i in range(256):
                if hist[i] == 0 and start is None:
                    start = i
                elif hist[i] != 0 and start is not None:
                    if i - start > 10:  # Range of more than 10 empty values
                        zero_ranges.append((start, i-1))
                    start = None
            if start is not None and 255 - start > 10:
                zero_ranges.append((start, 255))
                
            if zero_ranges:
                print(f"    [!] {channel} channel has suspicious empty ranges:")
                for start, end in zero_ranges:
                    print(f"      Values {start}-{end} never used")
                    
    except Exception as e:
        print(f"    Error during histogram analysis: {e}")

###############################################################################
# 10) JPEG-specific checks
###############################################################################

def check_jpeg_comments(file_path: Path) -> None:
    """
    Check JPEG comment segments (COM markers) for hidden data.
    
    Args:
        file_path: Path to the JPEG file
    """
    logging.info("Checking JPEG comment segments...")
    
    with log_operation("Reading JPEG file", level=logging.DEBUG):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data.startswith(b'\xFF\xD8'):
            logging.info("Not a JPEG file - skipping comment analysis")
            return
    
    findings = 0
    with log_operation("Analyzing comment segments", level=logging.DEBUG):
        i = 0
        while i < len(data) - 1:
            if data[i] == 0xFF and data[i+1] == 0xFE:  # COM marker
                length = int.from_bytes(data[i+2:i+4], 'big')
                comment_data = data[i+4:i+2+length]
                
                logging.debug(f"Found comment segment at offset {i}, length {length}")
                
                # Try to decode as text
                try:
                    comment_text = comment_data.decode('utf-8', errors='ignore')
                    if any(tstr.lower() in comment_text.lower() for tstr in TARGET_STRINGS):
                        findings += 1
                        logging.warning(f"Found target string in comment at offset {i}")
                    
                    suspects = find_suspicious_strings(comment_text)
                    for s in suspects:
                        findings += 1
                        logging.warning(f"Suspicious string in comment at offset {i}: {s}")
                except UnicodeDecodeError:
                    pass
                
                # Check for ZIP signatures
                if comment_data.startswith(b'PK\x03\x04'):
                    findings += 1
                    logging.warning(f"Found ZIP signature in comment at offset {i}")
                
                # Check entropy
                entropy = calculate_entropy(comment_data)
                if entropy > 7.5:
                    findings += 1
                    logging.warning(f"High entropy ({entropy:.2f}) in comment at offset {i}")
                
                i += length + 2
            else:
                i += 1
    
    if findings:
        logging.info(f"Found {findings} suspicious patterns in JPEG comments")
    else:
        logging.info("No suspicious patterns found in JPEG comments")

def check_large_metadata(file_path: Path) -> None:
    """
    Check for large binary blobs in EXIF/IPTC metadata that could contain hidden data.
    
    Args:
        file_path: Path to the image file
    """
    logging.info("Checking for large metadata fields...")
    
    with log_operation("Reading metadata", level=logging.DEBUG):
        with open(file_path, 'rb') as f:
            tags = exifread.process_file(f)
        
        if not tags:
            logging.info("No metadata found")
            return
        
        logging.debug(f"Found {len(tags)} metadata tags")
    
    findings = 0
    with log_operation("Analyzing metadata fields", level=logging.DEBUG):
        for tag in tags:
            val = str(tags[tag])
            
            # Check for large binary values
            if len(val) > 1000:  # Arbitrary threshold
                logging.debug(f"Large metadata field found: {tag} ({len(val)} bytes)")
                
                # Check for base64
                if looks_like_base64(val):
                    findings += 1
                    logging.warning(f"Large base64-like content in {tag}")
                    
                    try:
                        decoded = base64.b64decode(val)
                        if decoded.startswith(b'PK\x03\x04'):
                            findings += 1
                            logging.warning(f"Base64-encoded ZIP found in {tag}")
                    except:
                        pass
                
                # Check entropy
                entropy = calculate_entropy(val.encode())
                if entropy > 7.5:
                    findings += 1
                    logging.warning(f"High entropy ({entropy:.2f}) in {tag}")
    
    if findings:
        logging.info(f"Found {findings} suspicious large metadata fields")
    else:
        logging.info("No suspicious large metadata fields found")

###############################################################################
# File handling and analysis
###############################################################################

def is_image_file(file_path: Path) -> bool:
    """Check if a file is an image based on its extension."""
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
    return file_path.suffix.lower() in image_extensions

def get_image_files(path: Path) -> List[Path]:
    """Get all image files from a directory recursively."""
    if path.is_file():
        return [path] if is_image_file(path) else []
    
    image_files = []
    for item in path.rglob("*"):
        if item.is_file() and is_image_file(item):
            image_files.append(item)
    return image_files

def setup_output_directory(base_path: Optional[Path] = None) -> Path:
    """Create and return the output directory path."""
    if base_path is None:
        base_path = Path("stego_analysis_results")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = base_path / f"analysis_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def analyze_file(file_path: Path) -> StegResults:
    """
    Analyze a single file and return results.
    
    Args:
        file_path: Path to the image file
        
    Returns:
        StegResults object containing the analysis results
    """
    results = StegResults(file_path)
    
    with log_operation(f"Analyzing {file_path.name}"):
        logging.info(f"File size: {file_path.stat().st_size:,} bytes")
        
        # Capture output from each analysis function
        analysis_functions = [
            (check_metadata, "metadata"),
            (check_raw_bytes, "raw_bytes"),
            (check_binary_patterns, "binary_patterns"),
            (check_multibit_lsb, "lsb"),
            (check_channels, "channels"),
            (check_binwalk, "binwalk"),
            (check_icc_profile, "icc_profile"),
            (check_zip_signatures, "zip_signatures"),
            (check_appended_data, "appended_data"),
            (check_histogram, "histogram"),
            (check_jpeg_comments, "jpeg_comments"),
            (check_large_metadata, "large_metadata")
        ]
        
        total_functions = len(analysis_functions)
        for i, (func, category) in enumerate(analysis_functions, 1):
            with log_operation(f"{category} analysis", level=logging.DEBUG):
                try:
                    with OutputCapture() as output:
                        func(file_path)
                        for line in output.captured_output:
                            if line.strip() and not line.startswith("[*]"):
                                results.add_finding(category, line.strip())
                                logging.debug(line.strip())
                except Exception as e:
                    error_msg = f"Error during {category} analysis: {str(e)}"
                    results.add_finding(category, error_msg)
                    logging.error(error_msg)
            
            log_progress(i, total_functions, "analysis steps completed")
        
        # Log summary of findings
        total_findings = sum(len(findings) for findings in results.findings.values())
        logging.info(f"Analysis complete - {total_findings} total findings")
        for category, findings in results.findings.items():
            if findings:
                logging.info(f"  {category}: {len(findings)} finding(s)")
    
    return results

###############################################################################
# Main
###############################################################################

def main() -> None:
    """
    Main entry point for the stego_check script.
    Analyzes image files for potential steganographic content.
    """
    # Create output directory
    output_dir = Path("stego_check_results")
    output_dir.mkdir(exist_ok=True)
    
    # Set up logging
    setup_logging(output_dir)
    
    # Parse arguments
    if len(sys.argv) != 2:
        logging.error("Usage: python stego_check.py <image_file_or_directory>")
        sys.exit(1)
    
    target_path = Path(sys.argv[1])
    
    # Validate path
    if not target_path.exists():
        logging.error(f"Path does not exist: {target_path}")
        sys.exit(1)
    
    logging.info(f"Results will be saved to {output_dir}")
    
    # Find image files
    image_files = []
    if target_path.is_file():
        if target_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            image_files = [target_path]
        else:
            logging.error(f"Not a supported image file: {target_path}")
            sys.exit(1)
    else:
        image_files = [
            f for f in target_path.rglob('*')
            if f.is_file() and f.suffix.lower() in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']
        ]
    
    if not image_files:
        logging.error("No image files found")
        sys.exit(1)
    
    logging.info(f"Found {len(image_files)} image files to analyze")
    
    # Process each file
    summary_file = output_dir / "analysis_summary.txt"
    with open(summary_file, 'w') as summary:
        for i, image_file in enumerate(image_files, 1):
            logging.info(f"\nAnalyzing file {i}/{len(image_files)}: {image_file}")
            
            try:
                with log_operation(f"Analyzing {image_file.name}"):
                    analyze_file(image_file)
            except Exception as e:
                logging.error(f"Error analyzing {image_file}: {e}")
                traceback.print_exc()
                continue
            
            # Add separator line
            summary.write("-" * 80 + "\n")
    
    logging.info(f"\nAnalysis complete. Summary written to {summary_file}")

if __name__ == "__main__":
    main()