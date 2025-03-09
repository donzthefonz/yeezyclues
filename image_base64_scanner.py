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
    Convert an image file to a base64 string.
    
    Args:
        image_path: Path to the image file
        
    Returns:
        Base64 encoded string of the image
    """
    with Image.open(image_path) as img:
        # Convert to RGB if necessary
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        
        # Save to bytes buffer
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        
        # Convert to base64
        return base64.b64encode(buffer.getvalue()).decode('utf-8')

def find_word_sequences(text: str, dictionary: enchant.Dict, min_length: int = 4, max_length: int = 10) -> Dict[str, Set[str]]:
    """
    Find word sequences and special patterns in text.
    
    Args:
        text: Text to search through
        dictionary: Enchant dictionary for word validation
        min_length: Minimum word length to search for (default: 4)
        max_length: Maximum word length to search for (default: 10)
        
    Returns:
        Dictionary containing found words and special patterns, with words sorted by length
    """
    start_time = time.time()
    print(f"Starting pattern search in text of length: {len(text)}")
    
    # Special patterns to look for (can be expanded)
    special_patterns = {
        '4NBT', 'FLAG', 'PASS', 'KEY=', 'PWD=', 'tina', 'tena', 'MMM', 'Destiny', 'kanye', 'ace', 'fish', 'wiz', 'moon', 'coin',
        'Y3S', 'Y34R', 'Y0UR', 'Y0L0', 'Y3T1', 'Y3WS', 'Y1P3', 'Y1PS', 'Y0BS', 'Y0GA', 'Y0G1', 'Y0K3', 'Y0LK', 'Y0R3', 'Y0WL',
        'YURT', 'ZANY', 'ZAPS', 'Z34L', 'Z3DS', 'Z3NS', 'Z3R0', 'Z3ST', 'Z3TA', 'Z1NC', 'Z1N3', 'Z1NG', 'Z1TS', 'Z0N3', 'Z00M',
        'Z00S', 'W1LL', 'BL4K3', 'CHRIST', 'H34L', 'W0M4N', '1SSU3', 'BL00D', '1780', 'M3M3', 'C01N', 'ARG', 'ST34LTH', 'PUZZL3',
        'BLAKE', 'william', 'aeri', 'yzy', 'yeezy', 'nero', 'milo', 'bear', 'pump', 'chori', 'wizk', 'etha', 'fine', 'dest', 
        'bianc', 'plut', 'blak', 'jews', 'donda', 'hitle', 'jewm', 'cryp', 'elon', 'reap', 'west', 'nort', 'kimk', 'lore', 
        'tate', 'anse', 'hold', 'hodl', 'ansem', 'faith', 'ye', 'jesus', 'bound', 'ultralight', 'beam', 'famous', 'wolves', 
        'fade', 'ghost', 'town', 'violent', 'crimes', 'saint', 'pablo', 'yeezus', 'heartless', 'stronger', 'gold', 'digger'
    }
    
    results = {
        'special_patterns': set(),
        'words': set()
    }
    
    text = text.upper()  # Normalize to uppercase
    
    # First check for special patterns
    pattern_start = time.time()
    print("Checking special patterns...")
    for pattern in special_patterns:
        if pattern.upper() in text:
            results['special_patterns'].add(pattern.upper())
    log_time(pattern_start, "Special pattern check completed")
    
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
    log_time(start_time, "Total pattern finding time")
    print(f"Found {len(results['special_patterns'])} special patterns and {len(results['words'])} words")
    
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
        'special_patterns': list(sorted(findings['special_patterns'])),
        'words': sorted_words,
        'original_image_name': image_path.name,
        'scan_timestamp': datetime.now().isoformat()
    }
    
    with open(image_dir / "findings.json", "w") as f:
        json.dump(findings_dict, f, indent=4)
    
    # Create a human-readable summary
    with open(image_dir / "summary.txt", "w") as f:
        f.write(f"Scan Results for: {image_path.name}\n")
        f.write(f"Scan Time: {datetime.now().isoformat()}\n\n")
        
        if findings['special_patterns']:
            f.write("Special Patterns Found:\n")
            for pattern in sorted(findings['special_patterns']):
                f.write(f"  - {pattern}\n")
        else:
            f.write("No special patterns found.\n")
            
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
        pattern_occurrences: Dict[str, Set[str]] = {}
        images_with_patterns = 0
        
        # First pass: collect all pattern occurrences
        for finding in all_findings:
            if finding['special_patterns']:
                images_with_patterns += 1
                for pattern in finding['special_patterns']:
                    if pattern not in pattern_occurrences:
                        pattern_occurrences[pattern] = set()
                    pattern_occurrences[pattern].add(finding['original_image_name'])
        
        # Write per-file summary focusing on special patterns
        f.write("SPECIAL PATTERNS BY IMAGE\n")
        f.write("========================\n\n")
        
        for finding in all_findings:
            f.write(f"Image: {finding['original_image_name']}\n")
            if finding['special_patterns']:
                for pattern in sorted(finding['special_patterns']):
                    f.write(f"  - {pattern}\n")
            else:
                f.write("  No special patterns found\n")
            f.write("\n")
        
        # Write consolidated pattern summary
        f.write("\nCONSOLIDATED PATTERN SUMMARY\n")
        f.write("===========================\n\n")
        
        if pattern_occurrences:
            # Sort patterns by frequency
            sorted_patterns = sorted(
                pattern_occurrences.items(),
                key=lambda x: (len(x[1]), x[0]),
                reverse=True
            )
            
            for pattern, images in sorted_patterns:
                f.write(f"Pattern: {pattern}\n")
                f.write(f"Found in {len(images)} images: {', '.join(sorted(images))}\n\n")
        else:
            f.write("No special patterns found in any images.\n\n")
        
        # Write statistics
        f.write("\nSTATISTICS\n")
        f.write("==========\n")
        f.write(f"Images with special patterns: {images_with_patterns} out of {len(all_findings)}\n")
        f.write(f"Total unique patterns found: {len(pattern_occurrences)}\n")
        if pattern_occurrences:
            f.write("\nPattern frequency:\n")
            pattern_counts = {}
            for pattern, images in pattern_occurrences.items():
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
    if len(sys.argv) != 2:
        print("Usage: python image_base64_scanner.py <image_path_or_directory>")
        sys.exit(1)

    target_path = Path(sys.argv[1])
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        sys.exit(1)

    # Setup output directory with target path info
    output_dir = setup_output_directory(Path("scan_results"), target_path)
    print(f"Saving results to: {output_dir}")

    # Initialize the English dictionary
    dictionary = enchant.Dict("en_US")
    
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
            
            # Find sequences
            findings = find_word_sequences(base64_string, dictionary)
            
            # Save all results
            save_start = time.time()
            save_scan_results(output_dir, image_path, base64_string, findings)
            log_time(save_start, "Results saving completed")
            
            # Store findings for final summary
            findings_dict = {
                'special_patterns': findings['special_patterns'],
                'original_image_name': image_path.name
            }
            all_findings.append(findings_dict)
            
            # Print findings to console
            if findings['words'] or findings['special_patterns']:
                print("\nFound patterns:")
                if findings['special_patterns']:
                    print("  Special Patterns:")
                    for pattern in sorted(findings['special_patterns']):
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