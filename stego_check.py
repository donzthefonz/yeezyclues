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
            "zip_signatures": []  # New category for ZIP-related findings
        }
        self.has_findings = False

    def add_finding(self, category: str, finding: str) -> None:
        """Add a finding to the specified category."""
        self.findings[category].append(finding)
        self.has_findings = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert results to a dictionary format."""
        return {
            "file_name": self.file_path.name,
            "analysis_time": datetime.now().isoformat(),
            "findings": self.findings,
            "has_findings": self.has_findings
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
            "zip_signatures": {}
        }

    def write_file_results(self, results: StegResults) -> Path:
        """Write individual file results and return the result directory path."""
        # Create directory for this file's results
        result_dir = self.output_dir / results.file_path.stem
        result_dir.mkdir(parents=True, exist_ok=True)

        # Write detailed results
        with open(result_dir / "analysis.json", "w") as f:
            json.dump(results.to_dict(), f, indent=4)

        # Write human-readable summary
        with open(result_dir / "summary.txt", "w") as f:
            f.write(f"Analysis Results for: {results.file_path.name}\n")
            f.write(f"Analysis Time: {datetime.now().isoformat()}\n\n")
            
            for category, findings in results.findings.items():
                if findings:
                    f.write(f"{category.upper()} Findings:\n")
                    for finding in findings:
                        f.write(f"  - {finding}\n")
                    f.write("\n")

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
        print("\nWriting final summary...")  # Debug line
        
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
                        ) or "suspicious" in finding.lower()
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
            
            print(f"Final summary written to: {self.output_dir / 'final_summary.txt'}")  # Debug line

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

def find_suspicious_strings(text: str) -> List[str]:
    """
    Identify substrings in 'text' that look like they might be
    base64-encoded or hex-encoded strings. We do this very naively:
      - base64: mostly [A-Za-z0-9+/], possibly with '='
      - hex: mostly [0-9A-Fa-f]
    Return a list of suspicious substrings found.
    """
    suspicious = []
    # Rough scanning approach:
    words = text.split()
    for w in words:
        # Heuristic check: 
        # if it's > 8 chars, mostly base64 chars or mostly hex => suspect
        if len(w) > 8:
            # check base64
            if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in w):
                suspicious.append(f"Possible base64: {w}")
            # check hex
            elif all(c in "0123456789abcdefABCDEF" for c in w):
                suspicious.append(f"Possible hex: {w}")
    return suspicious

###############################################################################
# 1) Metadata scanning
###############################################################################

def check_metadata(file_path: Path) -> None:
    """
    Check image metadata for occurrences of "4NBT" or variants,
    plus suspicious encoded strings.
    """
    print("[*] Checking metadata...")
    with open(file_path, 'rb') as f:
        tags: Dict[str, Any] = exifread.process_file(f)

    for tag in tags:
        val = str(tags[tag])
        lower_val = val.lower()
        # Known patterns
        for tstr in TARGET_STRINGS:
            if tstr.lower() in lower_val:
                print(f"    Found '{tstr}' in metadata tag [{tag}] = {val}")
        for b64str in BASE64_VARIANTS:
            if b64str.lower() in lower_val:
                print(f"    Found base64-like '{b64str}' in metadata tag [{tag}] = {val}")
        # Also search suspicious strings
        suspects = find_suspicious_strings(lower_val)
        for s in suspects:
            print(f"    Suspicious string in metadata tag [{tag}]: {s}")

###############################################################################
# 2) Raw byte scanning
###############################################################################

def check_raw_bytes(file_path: Path) -> None:
    """
    Search for 4NBT and also look for suspicious ASCII or hex in the raw byte content.
    """
    print("[*] Checking raw bytes...")
    with open(file_path, 'rb') as f:
        data = f.read()
    # ASCII
    ascii_data = data.decode('latin-1', errors='ignore')
    lower_ascii = ascii_data.lower()
    # Hex
    hex_string = data.hex()

    # (A) Known patterns
    for tstr in TARGET_STRINGS:
        if tstr.lower() in lower_ascii:
            print(f"    Found '{tstr}' in raw ASCII data!")
    if "344e4254" in hex_string:
        print("    Found hex pattern '34 4E 42 54' (4NBT)!")
    if "54424e34" in hex_string:
        print("    Found reversed hex pattern '54 42 4E 34' (TBN4)!")

    for b64str in BASE64_VARIANTS:
        if b64str.lower() in lower_ascii:
            print(f"    Found base64-like '{b64str}' in raw ASCII data!")

    # (B) Suspicious-encoded substrings
    suspects = find_suspicious_strings(ascii_data)
    for s in suspects:
        print(f"    Suspicious substring in raw data: {s}")

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
    """Analyze a single file and return results."""
    results = StegResults(file_path)
    
    # Capture output from each analysis function
    analysis_functions = [
        (check_metadata, "metadata"),
        (check_raw_bytes, "raw_bytes"),
        (check_binary_patterns, "binary_patterns"),
        (check_multibit_lsb, "lsb"),
        (check_channels, "channels"),
        (check_binwalk, "binwalk"),
        (check_icc_profile, "icc_profile"),
        (check_zip_signatures, "zip_signatures")
    ]
    
    for func, category in analysis_functions:
        with OutputCapture() as output:
            try:
                func(file_path)
                for line in output.captured_output:
                    if line.strip() and not line.startswith("[*]"):
                        results.add_finding(category, line.strip())
            except Exception as e:
                results.add_finding(category, f"Error during analysis: {str(e)}")
    
    return results

###############################################################################
# Main
###############################################################################

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python stego_check.py <image_file_or_directory>")
        sys.exit(1)
    
    target_path = Path(sys.argv[1])
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        sys.exit(1)
    
    # Setup output directory
    output_dir = setup_output_directory()
    result_writer = ResultWriter(output_dir)
    
    # Get files to analyze
    files_to_analyze = get_image_files(target_path)
    if not files_to_analyze:
        print(f"No image files found in: {target_path}")
        sys.exit(1)
    
    print(f"Found {len(files_to_analyze)} image file(s) to analyze")
    print(f"Results will be saved to: {output_dir}\n")
    
    # Analyze each file
    for i, file_path in enumerate(files_to_analyze, 1):
        print(f"[{i}/{len(files_to_analyze)}] Analyzing: {file_path.name}")
        results = analyze_file(file_path)
        result_dir = result_writer.write_file_results(results)
        print(f"Results saved to: {result_dir}\n")
    
    # Write final summary
    result_writer.write_final_summary()
    print(f"\nAnalysis complete! Final summary saved to: {output_dir / 'final_summary.txt'}")

if __name__ == "__main__":
    main()