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
    
    Args:
        path: Path to an image file or directory containing images
        
    Yields:
        Path objects for each image file found
    """
    if path.is_file():
        if path.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}:
            yield path
    else:
        for item in path.glob('**/*'):
            if item.is_file() and item.suffix.lower() in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}:
                yield item

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

def find_word_sequences(text: str, dictionary: enchant.Dict | None, min_length: int = 4, max_length: int = 10) -> Dict[str, Set[str]]:
    """
    Find word sequences and special patterns in text.
    
    Args:
        text: Text to search through
        dictionary: Enchant dictionary for word validation, or None to skip word search
        min_length: Minimum word length to search for (default: 4)
        max_length: Maximum word length to search for (default: 10)
        
    Returns:
        Dictionary containing found words and special patterns, with words sorted by length
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
    low_significance_patterns = {
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
        'missing_contract_words': set(),
        'high_significance_patterns': set(),
        'low_significance_patterns': set(),
        'words': set(),
        'has_complete_contract': False,  # Track if all contract words are found
        'contract_words_ratio': {'found': 0, 'total': total_contract_words}  # Track ratio of found words
    }
    
    text = text.upper()  # Normalize to uppercase
    
    # Check for contract words first (highest priority)
    pattern_start = time.time()
    print("Checking contract words...")
    
    # Check each contract word and track missing ones
    for pattern in contract_words:
        pattern_upper = pattern.upper()
        if pattern_upper in text:
            results['contract_words'].add(pattern_upper)
        else:
            results['missing_contract_words'].add(pattern_upper)
    
    # Update contract word stats
    results['contract_words_ratio']['found'] = len(results['contract_words'])
    results['has_complete_contract'] = results['contract_words_ratio']['found'] == total_contract_words
    
    if results['has_complete_contract']:
        print(f"!!! COMPLETE CONTRACT FOUND !!! ({results['contract_words_ratio']['found']}/{total_contract_words} words)")
    else:
        print(f"Partial contract match ({results['contract_words_ratio']['found']}/{total_contract_words} words)")
        print(f"Missing contract words: {', '.join(sorted(results['missing_contract_words']))}")
    
    # Check for high significance patterns
    print("Checking high significance patterns...")
    for pattern in high_significance_patterns:
        if pattern.upper() in text:
            results['high_significance_patterns'].add(pattern.upper())
    
    print("Checking low significance patterns...")
    for pattern in low_significance_patterns:
        if pattern.upper() in text:
            results['low_significance_patterns'].add(pattern.upper())
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
          f"{len(results['low_significance_patterns'])} low significance patterns" +
          (f" and {len(results['words'])} words" if dictionary is not None else ""))
    
    return results

def save_scan_results(
    output_dir: Path,
    image_path: Path,
    base64_string: str,
    findings: Dict[str, Set[str]]
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
    image_dir.mkdir(exist_ok=True)
    
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
        'missing_contract_words': list(sorted(findings['missing_contract_words'])),
        'high_significance_patterns': list(sorted(findings['high_significance_patterns'])),
        'low_significance_patterns': list(sorted(findings['low_significance_patterns'])),
        'words': sorted_words,
        'has_complete_contract': findings['has_complete_contract'],
        'contract_words_ratio': findings['contract_words_ratio'],
        'original_image_name': image_path.name,
        'scan_timestamp': datetime.now().isoformat()
    }
    
    with open(image_dir / "findings.json", "w") as f:
        json.dump(findings_dict, f, indent=4)
    
    # Create a human-readable summary
    with open(image_dir / "summary.txt", "w") as f:
        f.write(f"Scan Results for: {image_path.name}\n")
        f.write(f"Scan Time: {datetime.now().isoformat()}\n\n")
        
        ratio = findings['contract_words_ratio']
        if findings['has_complete_contract']:
            f.write(f"!!! COMPLETE CONTRACT FOUND !!! ({ratio['found']}/{ratio['total']} words)\n\n")
        
        if findings['contract_words'] or findings['high_significance_patterns'] or findings['low_significance_patterns']:
            f.write("Contract Words and Patterns Found:\n")
            if findings['contract_words']:
                f.write(f"  - Contract Words Found ({ratio['found']}/{ratio['total']}):\n")
                for word in sorted(findings['contract_words']):
                    f.write(f"    - {word}\n")
                if not findings['has_complete_contract']:
                    f.write("\n  - Missing Contract Words:\n")
                    for word in sorted(findings['missing_contract_words']):
                        f.write(f"    - {word}\n")
            if findings['high_significance_patterns']:
                f.write("  - High Significance Patterns:\n")
                for pattern in sorted(findings['high_significance_patterns']):
                    f.write(f"    - {pattern}\n")
            if findings['low_significance_patterns']:
                f.write("  - Low Significance Patterns:\n")
                for pattern in sorted(findings['low_significance_patterns']):
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
    
    with open(output_dir / "final_summary.txt", "w") as f:
        f.write("BASE64 SCAN ANALYSIS SUMMARY\n")
        f.write("===========================\n\n")
        f.write(f"Analysis completed at: {datetime.now().isoformat()}\n")
        f.write(f"Total images analyzed: {len(all_findings)}\n\n")
        
        # Track patterns across all files
        contract_words_occurrences: Dict[str, Set[str]] = {}
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
                        contract_words_occurrences[pattern] = set()
                    contract_words_occurrences[pattern].add(finding['original_image_name'])
            
            if finding['high_significance_patterns']:
                images_with_high_significance += 1
                for pattern in finding['high_significance_patterns']:
                    if pattern not in high_significance_occurrences:
                        high_significance_occurrences[pattern] = set()
                    high_significance_occurrences[pattern].add(finding['original_image_name'])
            
            if finding['low_significance_patterns']:
                images_with_low_significance += 1
                for pattern in finding['low_significance_patterns']:
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
                    f.write(f"  - {finding['original_image_name']} ({ratio['found']}/{ratio['total']} words)\n")
            f.write("\n")
        
        # Write per-file summary
        f.write("PATTERNS BY IMAGE\n")
        f.write("================\n\n")
        
        for finding in all_findings:
            f.write(f"Image: {finding['original_image_name']}\n")
            ratio = finding.get('contract_words_ratio', {'found': len(finding['contract_words']), 'total': 11})  # Default to 11 total contract words if ratio not found
            if finding.get('has_complete_contract', False):
                f.write(f"  !!! COMPLETE CONTRACT FOUND !!! ({ratio['found']}/{ratio['total']} words)\n")
            if finding['contract_words']:
                f.write(f"  CONTRACT WORDS ({ratio['found']}/{ratio['total']}):\n")
                for word in sorted(finding['contract_words']):
                    f.write(f"    - {word}\n")
            if finding['high_significance_patterns']:
                f.write("  HIGH SIGNIFICANCE PATTERNS:\n")
                for pattern in sorted(finding['high_significance_patterns']):
                    f.write(f"    - {pattern}\n")
            if finding['low_significance_patterns']:
                f.write("  Low Significance Patterns:\n")
                for pattern in sorted(finding['low_significance_patterns']):
                    f.write(f"    - {pattern}\n")
            if not (finding['contract_words'] or finding['high_significance_patterns'] or finding['low_significance_patterns']):
                f.write("  No patterns found\n")
            f.write("\n")
        
        # Write consolidated pattern summary
        f.write("\nCONSOLIDATED PATTERN SUMMARY\n")
        f.write("===========================\n\n")
        
        if contract_words_occurrences:
            f.write("CONTRACT WORDS\n")
            f.write("=============\n")
            # Sort contract words by frequency
            sorted_patterns = sorted(
                contract_words_occurrences.items(),
                key=lambda x: (len(x[1]), x[0]),
                reverse=True
            )
            
            for pattern, images in sorted_patterns:
                f.write(f"Pattern: {pattern}\n")
                f.write(f"Found in {len(images)} images: {', '.join(sorted(images))}\n\n")
        
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
            f.write("\nLow Significance Patterns\n")
            f.write("=======================\n")
            # Sort low significance patterns by frequency
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
        f.write(f"Images with low significance patterns: {images_with_low_significance} out of {len(all_findings)}\n")
        f.write(f"Total unique contract words found: {len(contract_words_occurrences)}\n")
        f.write(f"Total unique high significance patterns found: {len(high_significance_occurrences)}\n")
        f.write(f"Total unique low significance patterns found: {len(low_significance_occurrences)}\n")
        
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
            f.write("\nLow Significance Pattern Frequency:\n")
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
                'high_significance_patterns': findings['high_significance_patterns'],
                'low_significance_patterns': findings['low_significance_patterns'],
                'original_image_name': image_path.name,
                'has_complete_contract': findings['has_complete_contract'],
                'contract_words_ratio': findings['contract_words_ratio']  # Add the ratio information
            }
            all_findings.append(findings_dict)
            
            # Print findings to console
            if findings['words'] or findings['contract_words'] or findings['high_significance_patterns'] or findings['low_significance_patterns']:
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
                if findings['high_significance_patterns'] or findings['low_significance_patterns']:
                    print("  High and Low Significance Patterns:")
                    if findings['high_significance_patterns']:
                        for pattern in sorted(findings['high_significance_patterns']):
                            print(f"    - {pattern}")
                    if findings['low_significance_patterns']:
                        for pattern in sorted(findings['low_significance_patterns']):
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