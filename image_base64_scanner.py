import sys
import os
import json
from pathlib import Path
import base64
from typing import List, Set, Iterator, Dict, Any
from PIL import Image
import io
import enchant  # for word validation
import shutil
from datetime import datetime
import time  # Add timing functionality
import argparse

def log_time(start_time: float, message: str) -> None:
    """
    Log elapsed time with a message.
    
    Args:
        start_time: Starting timestamp
        message: Message to display with timing
    """
    elapsed = time.time() - start_time
    print(f"{message}: {elapsed:.2f} seconds")

def setup_output_directory(base_dir: Path, target_path: Path) -> Path:
    """
    Create and return path to output directory with readable date and optional filename.
    
    Args:
        base_dir: Base directory path where scan results will be stored
        target_path: Path to the target file or directory being scanned
        
    Returns:
        Path to the newly created output directory
    """
    readable_date = datetime.now().strftime("%B_%d_%Y_%H-%M")  # e.g. March_21_2024_14-30
    
    if target_path.is_file():
        # For single file, include the filename in the directory name
        output_dir = base_dir / f"scan_{target_path.stem}_{readable_date}"
    else:
        # For directories, just use the date
        output_dir = base_dir / f"scan_results_{readable_date}"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir

def get_image_files(path: Path) -> Iterator[Path]:
    """
    Yield all image files from a directory or a single image file.
    Skip files larger than 2.7MB.
    
    Args:
        path: Path to an image file or directory containing images
        
    Yields:
        Path objects for each image file found that are under size limit
    """
    MAX_SIZE_BYTES = 2.7 * 1024 * 1024  # 2.7MB in bytes
    
    if path.is_file():
        if path.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}:
            if path.stat().st_size <= MAX_SIZE_BYTES:
                yield path
            else:
                print(f"Skipping {path.name}: File size {path.stat().st_size / (1024*1024):.1f}MB exceeds limit of 2.7MB")
    else:
        for item in path.glob('**/*'):
            if item.is_file() and item.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}:
                if item.stat().st_size <= MAX_SIZE_BYTES:
                    yield item
                else:
                    print(f"Skipping {item.name}: File size {item.stat().st_size / (1024*1024):.1f}MB exceeds limit of 2.7MB")

def image_to_base64(image_path: Path) -> str:
    """
    Convert an image file to a base64 string, preserving original format.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        Base64 encoded string of the image with appropriate data URI prefix
    """
    # Read the file directly as bytes instead of using PIL
    with open(image_path, 'rb') as image_file:
        base64_string = base64.b64encode(image_file.read()).decode('utf-8')
        
    # Get the MIME type based on file extension
    mime_type = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.webp': 'image/webp'
    }.get(image_path.suffix.lower(), 'image/jpeg')
    
    # Return with data URI prefix
    return f"data:{mime_type};base64,{base64_string}"

def find_word_sequences(text: str, dictionary: enchant.Dict | None, min_length: int = 4, max_length: int = 10) -> Dict[str, Set[str] | Dict[str, int]]:
    """
    Find word sequences and special patterns in text.
    
    Args:
        text: Text to search through
        dictionary: Enchant dictionary for word validation, or None to skip word search
        min_length: Minimum word length to search for (default: 4)
        max_length: Maximum word length to search for (default: 10)
        
    Returns:
        Dictionary containing found words, special patterns, contract word counts, and character count
    """
    start_time = time.time()
    print(f"Starting pattern search in text of length: {len(text)}")
    
    # Contract words - highest priority, direct components of the contract
    contract_words = {
        '4NBT', 'F8PF', 'LH4O', 'LFNW', 'F3KN', 'V46F', 'Y9I5', 'OXJD', 'XFFC', 'ETXR', 'PUMP'
    }
    total_contract_words = len(contract_words)
    
    # High significance patterns - critical identifiers and key terms
    high_significance_patterns = {
        'YZY', 'YEEZY', 'KANYE', 'YE',  # Primary Yeezy/Kanye identifiers
        'FLAG', 'PASS', 'KEY=', 'PWD=', 'OLAF'  # Common steganography markers
    }
    
    # Lower significance patterns - contextual or thematic terms
    other_significance_patterns = {
        # Kanye/Yeezy related
        'WEST', 'PABLO', 'YEEZUS', 'DONDA', 'ULTRALIGHT', 'BEAM', 'FAMOUS', 
        'WOLVES', 'FADE', 'GHOST', 'TOWN', 'VIOLENT', 'CRIMES', 'SAINT',
        'HEARTLESS', 'STRONGER', 'GOLD', 'DIGGER',
        
        # Common encoding patterns
        'Y3S', 'Y34R', 'Y0UR', 'Y0L0', 'Y3T1', 'Y3WS', 'Y1P3', 'Y1PS',
        'Y0BS', 'Y0GA', 'Y0G1', 'Y0K3', 'Y0LK', 'Y0R3', 'Y0WL', 'YURT',
        'ZANY', 'ZAPS', 'Z34L', 'Z3DS', 'Z3NS', 'Z3R0', 'Z3ST', 'Z3TA',
        'Z1NC', 'Z1N3', 'Z1NG', 'Z1TS', 'Z0N3', 'Z00M', 'Z00S', 'W1LL',
        
        # Other contextual terms
        'TINA', 'TENA', 'MMM', 'DESTINY', 'ACE', 'FISH', 'WIZ', 'MOON', 'COIN',
        'BL4K3', 'CHRIST', 'H34L', 'W0M4N', '1SSU3', 'BL00D', '1780', 'M3M3',
        'C01N', 'ARG', 'ST34LTH', 'PUZZL3', 'BLAKE', 'WILLIAM', 'AERI', 'NERO',
        'MILO', 'BEAR', 'CHORI', 'WIZK', 'ETHA', 'FINE', 'DEST', 'BIANC',
        'PLUT', 'BLAK', 'JEWS', 'JEWM', 'CRYP', 'ELON', 'REAP', 'NORT',
        'KIMK', 'LORE', 'TATE', 'ANSE', 'HOLD', 'HODL', 'ANSEM', 'FAITH',
        'BOUND', 'JESUS', 'MEME'
    }
    
    results = {
        'contract_words': set(),
        'contract_word_counts': {},  # New field to track counts
        'missing_contract_words': set(),
        'high_significance_patterns': set(),
        'other_significance_patterns': set(),
        'words': set(),
        'has_complete_contract': False,  # Track if all contract words are found
        'contract_words_ratio': {'found': 0, 'total': total_contract_words},  # Track ratio of found words
        'character_count': len(text)  # Add character count to results
    }
    
    text = text.upper()  # Normalize to uppercase
    
    # Check for contract words first (highest priority)
    pattern_start = time.time()
    print("Checking contract words...")
    
    # Check each contract word and track missing ones and counts
    for pattern in contract_words:
        pattern_upper = pattern.upper()
        count = text.count(pattern_upper)
        if count > 0:
            results['contract_words'].add(pattern_upper)
            results['contract_word_counts'][pattern_upper] = count
        else:
            results['missing_contract_words'].add(pattern_upper)
    
    # Update contract word stats
    results['contract_words_ratio']['found'] = len(results['contract_words'])
    results['has_complete_contract'] = results['contract_words_ratio']['found'] == total_contract_words
    
    if results['has_complete_contract']:
        print(f"!!! COMPLETE CONTRACT FOUND !!! ({results['contract_words_ratio']['found']}/{total_contract_words} words)")
        for word, count in sorted(results['contract_word_counts'].items()):
            print(f"  - {word}: {count} occurrences")
    else:
        print(f"Partial contract match ({results['contract_words_ratio']['found']}/{total_contract_words} words)")
        if results['contract_word_counts']:
            print("Found contract words:")
            for word, count in sorted(results['contract_word_counts'].items()):
                print(f"  - {word}: {count} occurrences")
        print(f"Missing contract words: {', '.join(sorted(results['missing_contract_words']))}")
    
    # Check for high significance patterns
    print("Checking high significance patterns...")
    for pattern in high_significance_patterns:
        if pattern.upper() in text:
            results['high_significance_patterns'].add(pattern.upper())
    
    print("Checking other significance patterns...")
    for pattern in other_significance_patterns:
        if pattern.upper() in text:
            results['other_significance_patterns'].add(pattern.upper())
    log_time(pattern_start, "Special pattern check completed")
    
    # Only perform word search if dictionary is provided
    if dictionary is not None:
        # Then scan through the text with a sliding window for words
        word_start = time.time()
        total_windows = sum(len(text) - length + 1 for length in range(min_length, max_length + 1))
        windows_processed = 0
        last_progress = 0
        
        print("Starting word search...")
        for length in range(min_length, max_length + 1):
            length_start = time.time()
            windows_for_length = len(text) - length + 1
            
            for i in range(windows_for_length):
                sequence = text[i:i+length]
                windows_processed += 1
                
                # Update progress every 5%
                progress = (windows_processed * 100) // total_windows
                if progress >= last_progress + 5:
                    print(f"Word search progress: {progress}% ({len(results['words'])} words found)")
                    last_progress = progress
                
                # Check if it's all letters and a valid word
                if sequence.isalpha() and dictionary.check(sequence.lower()):
                    results['words'].add(sequence)
            
            log_time(length_start, f"Completed search for {length}-letter words")
        
        log_time(word_start, "Word search completed")
    else:
        print("Skipping word search as requested")
    
    log_time(start_time, "Total pattern finding time")
    print(f"Found {len(results['contract_words'])} contract words, " +
          f"{len(results['high_significance_patterns'])} high significance patterns, " +
          f"{len(results['other_significance_patterns'])} other significance patterns" +
          (f" and {len(results['words'])} words" if dictionary is not None else ""))
    
    return results

def save_scan_results(
    output_dir: Path,
    image_path: Path,
    base64_string: str,
    findings: Dict[str, Set[str] | Dict[str, int]]
) -> None:
    """
    Save scan results in an organized directory structure.
    
    Args:
        output_dir: Base output directory
        image_path: Path to the original image
        base64_string: Base64 encoded image data
        findings: Dictionary of found patterns and words
    """
    # Create directory for this image using its name
    image_dir = output_dir / image_path.stem
    
    # If all contract words are found, place in matched subfolder
    if findings['has_complete_contract']:
        image_dir = output_dir / "matched" / image_path.stem
        
    image_dir.mkdir(parents=True, exist_ok=True)
    
    # Save original image copy
    shutil.copy2(image_path, image_dir / f"original{image_path.suffix}")
    
    # Save base64 data
    with open(image_dir / "image_base64.txt", "w") as f:
        f.write(base64_string)
    
    # Sort words by length in descending order
    sorted_words = sorted(findings['words'], key=len, reverse=True)
    
    # Save findings as JSON
    findings_dict = {
        'contract_words': list(sorted(findings['contract_words'])),
        'contract_word_counts': dict(sorted(findings['contract_word_counts'].items())),
        'missing_contract_words': list(sorted(findings['missing_contract_words'])),
        'high_significance_patterns': list(sorted(findings['high_significance_patterns'])),
        'other_significance_patterns': list(sorted(findings['other_significance_patterns'])),
        'words': sorted_words,
        'has_complete_contract': findings['has_complete_contract'],
        'contract_words_ratio': findings['contract_words_ratio'],
        'original_image_name': image_path.name,
        'scan_timestamp': datetime.now().isoformat(),
        'character_count': findings['character_count']  # Add character count to JSON
    }
    
    with open(image_dir / "findings.json", "w") as f:
        json.dump(findings_dict, f, indent=4)
    
    # Create a human-readable summary
    with open(image_dir / "summary.txt", "w") as f:
        f.write(f"Scan Results for: {image_path.name}\n")
        f.write(f"Scan Time: {datetime.now().isoformat()}\n")
        f.write(f"Base64 Character Count: {findings['character_count']}\n\n")  # Add character count to summary
        
        ratio = findings.get('contract_words_ratio', {'found': len(findings['contract_words']), 'total': 11})
        if findings['has_complete_contract']:
            f.write(f"!!! COMPLETE CONTRACT FOUND !!! ({ratio['found']}/{ratio['total']} words)\n\n")
        
        if findings['contract_words'] or findings['high_significance_patterns'] or findings['other_significance_patterns']:
            f.write("Contract Words and Patterns Found:\n")
            if findings['contract_words']:
                f.write(f"  - Contract Words Found ({ratio['found']}/{ratio['total']}):\n")
                for word in sorted(findings['contract_words']):
                    count = findings['contract_word_counts'].get(word, 0)
                    f.write(f"    - {word} ({count} occurrences)\n")
                if not findings['has_complete_contract']:
                    f.write("\n  - Missing Contract Words:\n")
                    for word in sorted(findings['missing_contract_words']):
                        f.write(f"    - {word}\n")
            if findings['high_significance_patterns']:
                f.write("  - High Significance Patterns:\n")
                for pattern in sorted(findings['high_significance_patterns']):
                    f.write(f"    - {pattern}\n")
            if findings['other_significance_patterns']:
                f.write("  - other significance Patterns:\n")
                for pattern in sorted(findings['other_significance_patterns']):
                    f.write(f"    - {pattern}\n")
        else:
            f.write("No contract words or patterns found.\n")
            
        if findings['words']:
            f.write("\nFound Words (by length):\n")
            for word in sorted_words:
                f.write(f"  - {word} ({len(word)} letters)\n")
        else:
            f.write("\nNo words found.\n")

def write_final_summary(output_dir: Path, all_findings: List[Dict[str, Any]]) -> None:
    """
    Write a consolidated final summary of all image analyses.
    
    Args:
        output_dir: Directory to save the summary
        all_findings: List of findings dictionaries for all processed images
    """
    print("\nGenerating final summary...")
    
    # Original contract words order
    contract_words_order = [
        '4NBT', 'F8PF', 'LH4O', 'LFNW', 'F3KN', 'V46F', 'Y9I5', 'OXJD', 'XFFC', 'ETXR', 'PUMP'
    ]
    
    with open(output_dir / "final_summary.txt", "w") as f:
        f.write("BASE64 SCAN ANALYSIS SUMMARY\n")
        f.write("===========================\n\n")
        f.write(f"Analysis completed at: {datetime.now().isoformat()}\n")
        f.write(f"Total images analyzed: {len(all_findings)}\n")
        
        # Separate complete and incomplete contract images
        complete_contract_images = [f for f in all_findings if f.get('has_complete_contract', False)]
        incomplete_contract_images = [f for f in all_findings if not f.get('has_complete_contract', False)]
        
        # Calculate character count statistics
        total_chars = sum(finding.get('character_count', 0) for finding in all_findings)
        avg_chars = total_chars / len(all_findings) if all_findings else 0
        min_chars = min((finding.get('character_count', 0) for finding in all_findings), default=0)
        max_chars = max((finding.get('character_count', 0) for finding in all_findings), default=0)
        
        # Calculate character count statistics for complete contract images
        complete_total_chars = sum(finding.get('character_count', 0) for finding in complete_contract_images)
        complete_avg_chars = complete_total_chars / len(complete_contract_images) if complete_contract_images else 0
        
        # Calculate character count statistics for incomplete contract images
        incomplete_total_chars = sum(finding.get('character_count', 0) for finding in incomplete_contract_images)
        incomplete_avg_chars = incomplete_total_chars / len(incomplete_contract_images) if incomplete_contract_images else 0
        
        # Write character count statistics
        f.write("\nCHARACTER COUNT STATISTICS\n")
        f.write("========================\n")
        f.write(f"Total characters across all images: {total_chars:,}\n")
        f.write(f"Average characters per image: {avg_chars:,.2f}\n")
        f.write(f"Minimum characters in an image: {min_chars:,}\n")
        f.write(f"Maximum characters in an image: {max_chars:,}\n")
        
        # Write character count comparison if we have both types of images
        f.write("\nCharacter count by contract status:\n")
        if complete_contract_images:
            f.write(f"  Complete contracts ({len(complete_contract_images)} images): {complete_avg_chars:,.2f} chars avg\n")
            f.write(f"  Total characters: {complete_total_chars:,}\n")
        else:
            f.write("  No images with complete contracts found\n")
            
        if incomplete_contract_images:
            f.write(f"  Incomplete contracts ({len(incomplete_contract_images)} images): {incomplete_avg_chars:,.2f} chars avg\n")
            f.write(f"  Total characters: {incomplete_total_chars:,}\n")
        else:
            f.write("  No images with incomplete contracts found\n")
            
        # Only write comparison if we have both complete and incomplete contracts
        if complete_contract_images and incomplete_contract_images and incomplete_avg_chars > 0:
            char_diff = complete_avg_chars - incomplete_avg_chars
            f.write(f"\nComparison:\n")
            f.write(f"  Complete contracts have {abs(char_diff):,.2f} {'more' if char_diff > 0 else 'fewer'} characters on average\n")
            f.write(f"  Ratio of complete to incomplete average length: {(complete_avg_chars / incomplete_avg_chars):,.2f}x\n")
        f.write("\n")
        
        # Track patterns across all files
        contract_words_occurrences: Dict[str, Dict[str, int]] = {}  # Changed to track counts per file
        high_significance_occurrences: Dict[str, Set[str]] = {}
        low_significance_occurrences: Dict[str, Set[str]] = {}
        images_with_contract_words = 0
        images_with_complete_contract = 0
        images_with_high_significance = 0
        images_with_low_significance = 0
        
        # First pass: collect all pattern occurrences
        for finding in all_findings:
            if finding['contract_words']:
                images_with_contract_words += 1
                if finding.get('has_complete_contract', False):
                    images_with_complete_contract += 1
                for pattern in finding['contract_words']:
                    if pattern not in contract_words_occurrences:
                        contract_words_occurrences[pattern] = {}
                    # Store count for this file
                    if 'contract_word_counts' in finding:
                        contract_words_occurrences[pattern][finding['original_image_name']] = finding['contract_word_counts'].get(pattern, 1)
            
            if finding['high_significance_patterns']:
                images_with_high_significance += 1
                for pattern in finding['high_significance_patterns']:
                    if pattern not in high_significance_occurrences:
                        high_significance_occurrences[pattern] = set()
                    high_significance_occurrences[pattern].add(finding['original_image_name'])
            
            if finding['other_significance_patterns']:
                images_with_low_significance += 1
                for pattern in finding['other_significance_patterns']:
                    if pattern not in low_significance_occurrences:
                        low_significance_occurrences[pattern] = set()
                    low_significance_occurrences[pattern].add(finding['original_image_name'])
        
        # Write complete contract matches first if any found
        if images_with_complete_contract > 0:
            f.write("\n!!! COMPLETE CONTRACT MATCHES !!!\n")
            f.write("=============================\n")
            f.write(f"Found {images_with_complete_contract} images with complete contract matches:\n")
            for finding in all_findings:
                if finding.get('has_complete_contract', False):
                    ratio = finding.get('contract_words_ratio', {'found': 0, 'total': 0})
                    chars = finding.get('character_count', 0)
                    f.write(f"  - {finding['original_image_name']} ({ratio['found']}/{ratio['total']} words, {chars:,} chars)\n")
                    # Add counts for each contract word
                    if 'contract_word_counts' in finding:
                        for word in contract_words_order:  # Use contract_words_order to maintain consistent order
                            if word in finding['contract_word_counts']:
                                count = finding['contract_word_counts'][word]
                                f.write(f"    - {word} ({count} occurrences)\n")
            f.write("\n")
        
        # Write per-file summary
        f.write("PATTERNS BY IMAGE\n")
        f.write("================\n\n")
        
        for finding in all_findings:
            f.write(f"Image: {finding['original_image_name']} ({finding.get('character_count', 0):,} chars)\n")
            ratio = finding.get('contract_words_ratio', {'found': len(finding['contract_words']), 'total': 11})
            if finding.get('has_complete_contract', False):
                f.write(f"  !!! COMPLETE CONTRACT FOUND !!! ({ratio['found']}/{ratio['total']} words)\n")
            if finding['contract_words']:
                f.write(f"  CONTRACT WORDS ({ratio['found']}/{ratio['total']}):\n")
                # Write contract words in original order with counts
                for word in contract_words_order:
                    if word in finding['contract_words']:
                        count = finding['contract_word_counts'][word]  # Get count directly from contract_word_counts
                        f.write(f"    - {word} ({count} occurrences)\n")
                f.write("\n")  # Add spacing between sections
            if finding['high_significance_patterns']:
                f.write("  HIGH SIGNIFICANCE PATTERNS:\n")
                for pattern in sorted(finding['high_significance_patterns']):
                    f.write(f"    - {pattern}\n")
            if finding['other_significance_patterns']:
                f.write("  OTHER SIGNIFICANCE PATTERNS:\n")
                for pattern in sorted(finding['other_significance_patterns']):
                    f.write(f"    - {pattern}\n")
            if not (finding['contract_words'] or finding['high_significance_patterns'] or finding['other_significance_patterns']):
                f.write("  No patterns found\n")
            f.write("\n")
        
        # Write consolidated pattern summary
        f.write("\nCONSOLIDATED PATTERN SUMMARY\n")
        f.write("===========================\n\n")
        
        if contract_words_occurrences:
            f.write("CONTRACT WORDS\n")
            f.write("=============\n")
            # Write contract words in original order with counts
            for pattern in contract_words_order:
                if pattern in contract_words_occurrences:
                    occurrences = contract_words_occurrences[pattern]
                    total_occurrences = sum(occurrences.values())
                    f.write(f"Pattern: {pattern}\n")
                    f.write(f"Found {total_occurrences} times across {len(occurrences)} images:\n")
                    for image_name, count in sorted(occurrences.items()):
                        f.write(f"  - {image_name}: {count} occurrences\n")
                    f.write("\n")
        
        if high_significance_occurrences:
            f.write("\nHIGH SIGNIFICANCE PATTERNS\n")
            f.write("=======================\n")
            # Sort high significance patterns by frequency
            sorted_patterns = sorted(
                high_significance_occurrences.items(),
                key=lambda x: (len(x[1]), x[0]),
                reverse=True
            )
            
            for pattern, images in sorted_patterns:
                f.write(f"Pattern: {pattern}\n")
                f.write(f"Found in {len(images)} images: {', '.join(sorted(images))}\n\n")
        
        if low_significance_occurrences:
            f.write("\nOTHER SIGNIFICANCE PATTERNS\n")
            f.write("=======================\n")
            # Sort other significance patterns by frequency
            sorted_patterns = sorted(
                low_significance_occurrences.items(),
                key=lambda x: (len(x[1]), x[0]),
                reverse=True
            )
            
            for pattern, images in sorted_patterns:
                f.write(f"Pattern: {pattern}\n")
                f.write(f"Found in {len(images)} images: {', '.join(sorted(images))}\n\n")
        
        if not (contract_words_occurrences or high_significance_occurrences or low_significance_occurrences):
            f.write("No patterns found in any images.\n\n")
        
        # Write statistics
        f.write("\nSTATISTICS\n")
        f.write("==========\n")
        f.write(f"Images with complete contract matches: {images_with_complete_contract} out of {len(all_findings)}\n")
        f.write(f"Images with partial contract words: {images_with_contract_words - images_with_complete_contract} out of {len(all_findings)}\n")
        f.write(f"Images with high significance patterns: {images_with_high_significance} out of {len(all_findings)}\n")
        f.write(f"Images with other significance patterns: {images_with_low_significance} out of {len(all_findings)}\n")
        f.write(f"Total unique contract words found: {len(contract_words_occurrences)}\n")
        f.write(f"Total unique high significance patterns found: {len(high_significance_occurrences)}\n")
        f.write(f"Total unique other significance patterns found: {len(low_significance_occurrences)}\n")
        
        if contract_words_occurrences:
            f.write("\nContract Word Frequency:\n")
            pattern_counts = {}
            for pattern, images in contract_words_occurrences.items():
                count = len(images)
                if count not in pattern_counts:
                    pattern_counts[count] = 0
                pattern_counts[count] += 1
            
            for count in sorted(pattern_counts.keys(), reverse=True):
                f.write(f"  {count} image(s): {pattern_counts[count]} pattern(s)\n")
        
        if high_significance_occurrences:
            f.write("\nHigh Significance Pattern Frequency:\n")
            pattern_counts = {}
            for pattern, images in high_significance_occurrences.items():
                count = len(images)
                if count not in pattern_counts:
                    pattern_counts[count] = 0
                pattern_counts[count] += 1
            
            for count in sorted(pattern_counts.keys(), reverse=True):
                f.write(f"  {count} image(s): {pattern_counts[count]} pattern(s)\n")
        
        if low_significance_occurrences:
            f.write("\nOther Significance Pattern Frequency:\n")
            pattern_counts = {}
            for pattern, images in low_significance_occurrences.items():
                count = len(images)
                if count not in pattern_counts:
                    pattern_counts[count] = 0
                pattern_counts[count] += 1
            
            for count in sorted(pattern_counts.keys(), reverse=True):
                f.write(f"  {count} image(s): {pattern_counts[count]} pattern(s)\n")

def main() -> None:
    """
    Main function to process images and find word sequences.
    """
    parser = argparse.ArgumentParser(description='Scan base64-encoded images for patterns and words')
    parser.add_argument('path', help='Path to image file or directory')
    parser.add_argument('--include-words', action='store_true',
                       help='Include dictionary word search in addition to pattern matching')
    parser.add_argument('--max-word-length', type=int, default=6,
                       help='Maximum word length to search for when using --include-words (default: 6)')
    args = parser.parse_args()

    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        sys.exit(1)

    # Setup output directory with target path info
    output_dir = setup_output_directory(Path("scan_results"), target_path)
    print(f"Saving results to: {output_dir}")
    if args.include_words:
        print(f"Including dictionary word search up to {args.max_word_length} letters long")
    else:
        print("Pattern matching only mode (faster)")

    # Initialize the English dictionary only if word search is requested
    dictionary = enchant.Dict("en_US") if args.include_words else None
    
    # Process each image
    total_start = time.time()
    image_count = 0
    all_findings = []
    
    for image_path in get_image_files(target_path):
        image_count += 1
        try:
            image_start = time.time()
            print(f"\nProcessing image {image_count}: {image_path}")
            
            # Convert to base64
            base64_start = time.time()
            base64_string = image_to_base64(image_path)
            log_time(base64_start, "Base64 conversion completed")
            
            # Find sequences with custom max length
            findings = find_word_sequences(base64_string, dictionary, max_length=args.max_word_length)
            
            # Save all results
            save_start = time.time()
            save_scan_results(output_dir, image_path, base64_string, findings)
            log_time(save_start, "Results saving completed")
            
            # Store findings for final summary
            findings_dict = {
                'contract_words': findings['contract_words'],
                'contract_word_counts': findings['contract_word_counts'],  # Add the counts
                'high_significance_patterns': findings['high_significance_patterns'],
                'other_significance_patterns': findings['other_significance_patterns'],
                'original_image_name': image_path.name,
                'has_complete_contract': findings['has_complete_contract'],
                'contract_words_ratio': findings['contract_words_ratio']
            }
            all_findings.append(findings_dict)
            
            # Print findings to console
            if findings['words'] or findings['contract_words'] or findings['high_significance_patterns'] or findings['other_significance_patterns']:
                print("\nFound patterns:")
                if findings['contract_words']:
                    ratio = findings['contract_words_ratio']
                    if findings['has_complete_contract']:
                        print(f"  !!! COMPLETE CONTRACT FOUND !!! ({ratio['found']}/{ratio['total']} words)")
                    print(f"  - Contract Words Found ({ratio['found']}/{ratio['total']}):")
                    for word in sorted(findings['contract_words']):
                        print(f"    - {word}")
                    if not findings['has_complete_contract']:
                        print("\n  - Missing Contract Words:")
                        for word in sorted(findings['missing_contract_words']):
                            print(f"    - {word}")
                if findings['high_significance_patterns'] or findings['other_significance_patterns']:
                    print("  High and Other Significance Patterns:")
                    if findings['high_significance_patterns']:
                        for pattern in sorted(findings['high_significance_patterns']):
                            print(f"    - {pattern}")
                    if findings['other_significance_patterns']:
                        for pattern in sorted(findings['other_significance_patterns']):
                            print(f"    - {pattern}")
                if findings['words']:
                    print("  Words (showing first 10):")
                    for word in sorted(findings['words'])[:10]:
                        print(f"    - {word}")
                    if len(findings['words']) > 10:
                        print(f"    ... and {len(findings['words']) - 10} more")
            else:
                print("No interesting patterns found.")
                
            print(f"Results saved in: {output_dir / image_path.stem}")
            log_time(image_start, "Total processing time for this image")
                
        except Exception as e:
            print(f"Error processing {image_path}: {e}")

    # Write final summary
    write_final_summary(output_dir, all_findings)

    log_time(total_start, f"\nTotal processing time for {image_count} images")
    print(f"All results have been saved to: {output_dir}")
    print(f"Final summary available at: {output_dir / 'final_summary.txt'}")

if __name__ == "__main__":
    main() 