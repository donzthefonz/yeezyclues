from pathlib import Path
import base64
from typing import Dict, Set, List, Iterator, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
import shutil
import time

@dataclass
class ContractPatterns:
    """Stores the contract patterns and other significant patterns to search for."""
    contract_words: Set[str] = field(default_factory=lambda: {
        '4NBT', 'F8PF', 'LH4O', 'LFNW', 'F3KN', 'V46F', 
        'Y9I5', 'OXJD', 'XFFC', 'ETXR', 'PUMP'
    })
    # contract_words: Set[str] = field(default_factory=lambda: {
    #     '9TY6', 'DUg1','VSss','YH5t','FE95','qoq5','hnAG','Fak4','w3cn','72sJ','NCoV'
    # })
    
    
    high_significance_patterns: Set[str] = field(default_factory=lambda: {
        'YZY', 'YEEZY', 'KANYE', 'YE',  # Primary Yeezy/Kanye identifiers
        'FLAG', 'PASS', 'KEY=', 'PWD=', 'OLAF'  # Common steganography markers
    })
    
    other_significance_patterns: Set[str] = field(default_factory=lambda: {
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
        'PLUT', 'BLAK', 'JEWS', 'JEWM', 'CRYP', 'ELON', 'REAPER', 'NORT',
        'KIMK', 'LORE', 'TATE', 'ANSE', 'HOLD', 'HODL', 'ANSEM', 'FAITH', 'THOMAS', 'DOG',
        'BOUND', 'JESUS', 'MEME', "CRAZYACE", "TRIPLE", "TRIPLEM", "MMM", "FLED", "SAMMY", "SOVIET", "FINESSE","SHAGGY","SOVIET","SEEKER","",""
    })

@dataclass
class ImageScanResult:
    """Stores the results of scanning a single image."""
    image_path: Path
    base64_string: str
    contract_words: Set[str] = field(default_factory=set)
    contract_word_counts: Dict[str, int] = field(default_factory=dict)
    missing_contract_words: Set[str] = field(default_factory=set)
    high_significance_patterns: Set[str] = field(default_factory=set)
    other_significance_patterns: Set[str] = field(default_factory=set)
    has_complete_contract: bool = False
    character_count: int = 0
    contract_words_ratio: Dict[str, int] = field(default_factory=lambda: {'found': 0, 'total': 11})

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to a dictionary for JSON serialization."""
        return {
            'contract_words': sorted(list(self.contract_words)),
            'contract_word_counts': dict(sorted(self.contract_word_counts.items())),
            'missing_contract_words': sorted(list(self.missing_contract_words)),
            'high_significance_patterns': sorted(list(self.high_significance_patterns)),
            'other_significance_patterns': sorted(list(self.other_significance_patterns)),
            'has_complete_contract': self.has_complete_contract,
            'contract_words_ratio': self.contract_words_ratio,
            'original_image_name': self.image_path.name,
            'character_count': self.character_count
        }

class Base64PatternScanner:
    """Main class for scanning base64-encoded images for patterns."""
    
    def __init__(self, patterns: ContractPatterns = None):
        """
        Initialize the scanner with pattern definitions.
        
        Args:
            patterns: ContractPatterns object containing patterns to search for
        """
        self.patterns = patterns or ContractPatterns()
        
    def get_image_files(self, path: Path) -> Iterator[Path]:
        """
        Yield all valid image files from a path.
        
        Args:
            path: Path to an image file or directory
            
        Yields:
            Path objects for each valid image file found
        """
        valid_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
        
        if path.is_file():
            if path.suffix.lower() in valid_extensions:
                yield path
        else:
            for item in path.glob('**/*'):
                if item.is_file() and item.suffix.lower() in valid_extensions:
                    yield item

    def image_to_base64(self, image_path: Path) -> str:
        """
        Convert an image file to a base64 string.
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Base64 encoded string with data URI prefix
        """
        with open(image_path, 'rb') as image_file:
            base64_string = base64.b64encode(image_file.read()).decode('utf-8')
        
        mime_type = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.webp': 'image/webp'
        }.get(image_path.suffix.lower(), 'image/jpeg')
        
        return f"data:{mime_type};base64,{base64_string}"

    def scan_image(self, image_path: Path) -> ImageScanResult:
        """
        Scan a single image for patterns.
        
        Args:
            image_path: Path to the image file
            
        Returns:
            ImageScanResult containing all findings
        """
        print(f"\nProcessing: {image_path}")
        base64_string = self.image_to_base64(image_path)
        
        result = ImageScanResult(
            image_path=image_path,
            base64_string=base64_string,
            character_count=len(base64_string)
        )
        
        # Convert to uppercase for case-insensitive matching
        text = base64_string.upper()
        
        # Check each contract word and track counts
        for pattern in self.patterns.contract_words:
            pattern_upper = pattern.upper()
            count = text.count(pattern_upper)
            if count > 0:
                result.contract_words.add(pattern_upper)
                result.contract_word_counts[pattern_upper] = count
            else:
                result.missing_contract_words.add(pattern_upper)
        
        # Update contract word stats
        result.contract_words_ratio['found'] = len(result.contract_words)
        result.contract_words_ratio['total'] = len(self.patterns.contract_words)
        result.has_complete_contract = len(result.contract_words) == len(self.patterns.contract_words)
        
        # Check for high significance patterns
        for pattern in self.patterns.high_significance_patterns:
            if pattern.upper() in text:
                result.high_significance_patterns.add(pattern.upper())
        
        # Check for other significance patterns
        for pattern in self.patterns.other_significance_patterns:
            if pattern.upper() in text:
                result.other_significance_patterns.add(pattern.upper())
        
        return result

    def save_results(self, output_dir: Path, result: ImageScanResult) -> None:
        """
        Save scan results to appropriate directories.
        
        Args:
            output_dir: Base output directory
            result: ImageScanResult to save
        """
        # Create directory based on contract status
        base_dir = output_dir / ("matched" if result.has_complete_contract else "partial")
        image_dir = base_dir / result.image_path.stem
        image_dir.mkdir(parents=True, exist_ok=True)
        
        # Save original image copy
        shutil.copy2(result.image_path, image_dir / f"original{result.image_path.suffix}")
        
        # Save base64 data
        with open(image_dir / "image_base64.txt", "w") as f:
            f.write(result.base64_string)
        
        # Save findings as JSON
        with open(image_dir / "findings.json", "w") as f:
            json.dump(result.to_dict(), f, indent=4)
        
        # Create human-readable summary
        with open(image_dir / "summary.txt", "w") as f:
            self._write_summary(f, result)

    def _write_summary(self, f, result: ImageScanResult) -> None:
        """Write a human-readable summary of the scan results."""
        f.write(f"Scan Results for: {result.image_path.name}\n")
        f.write(f"Scan Time: {datetime.now().isoformat()}\n")
        f.write(f"Base64 Character Count: {result.character_count:,}\n\n")
        
        if result.has_complete_contract:
            f.write(f"!!! COMPLETE CONTRACT FOUND !!! ")
            f.write(f"({result.contract_words_ratio['found']}/{result.contract_words_ratio['total']} words)\n\n")
        
        if result.contract_words:
            f.write("Contract Words Found:\n")
            for word in sorted(result.contract_words):
                count = result.contract_word_counts[word]
                f.write(f"  - {word} ({count} occurrences)\n")
            
            if not result.has_complete_contract:
                f.write("\nMissing Contract Words:\n")
                for word in sorted(result.missing_contract_words):
                    f.write(f"  - {word}\n")
        
        if result.high_significance_patterns:
            f.write("\nHigh Significance Patterns:\n")
            for pattern in sorted(result.high_significance_patterns):
                f.write(f"  - {pattern}\n")
        
        if result.other_significance_patterns:
            f.write("\nOther Significance Patterns:\n")
            for pattern in sorted(result.other_significance_patterns):
                f.write(f"  - {pattern}\n")

    def write_final_summary(self, output_dir: Path, all_results: List[ImageScanResult]) -> None:
        """
        Write a consolidated summary of all scan results.
        
        Args:
            output_dir: Directory to save the summary
            all_results: List of all scan results
        """
        with open(output_dir / "final_summary.txt", "w") as f:
            f.write("BASE64 PATTERN SCAN SUMMARY\n")
            f.write("==========================\n\n")
            f.write(f"Analysis completed at: {datetime.now().isoformat()}\n")
            f.write(f"Total images analyzed: {len(all_results)}\n\n")
            
            # Separate complete and incomplete matches
            complete_matches = [r for r in all_results if r.has_complete_contract]
            incomplete_matches = [r for r in all_results if not r.has_complete_contract]
            
            # Character count statistics
            total_chars = sum(r.character_count for r in all_results)
            avg_chars = total_chars / len(all_results) if all_results else 0
            complete_avg = sum(r.character_count for r in complete_matches) / len(complete_matches) if complete_matches else 0
            incomplete_avg = sum(r.character_count for r in incomplete_matches) / len(incomplete_matches) if incomplete_matches else 0
            
            f.write("CHARACTER COUNT ANALYSIS\n")
            f.write("=======================\n")
            f.write(f"Total characters across all images: {total_chars:,}\n")
            f.write(f"Average characters per image: {avg_chars:,.2f}\n\n")
            
            if complete_matches:
                f.write(f"Complete contract matches ({len(complete_matches)} images):\n")
                f.write(f"  Average characters: {complete_avg:,.2f}\n")
                # Sort complete matches by character count
                sorted_complete_matches = sorted(complete_matches, key=lambda x: x.character_count)
                for result in sorted_complete_matches:
                    f.write(f"  - {result.image_path.name}: {result.character_count:,} chars\n")
                    for word, count in sorted(result.contract_word_counts.items()):
                        f.write(f"    {word}: {count} occurrences\n")
                f.write("\n")
            
            if incomplete_matches:
                f.write(f"Incomplete matches ({len(incomplete_matches)} images):\n")
                f.write(f"  Average characters: {incomplete_avg:,.2f}\n")
                for result in incomplete_matches:
                    f.write(f"  - {result.image_path.name}: {result.character_count:,} chars\n")
                    f.write(f"    Found {len(result.contract_words)} of {result.contract_words_ratio['total']} contract words\n")
                f.write("\n")
            
            if complete_matches and incomplete_matches:
                char_diff = complete_avg - incomplete_avg
                f.write("Character Count Comparison:\n")
                f.write(f"  Complete contracts have {abs(char_diff):,.2f} ")
                f.write(f"{'more' if char_diff > 0 else 'fewer'} characters on average\n")
                f.write(f"  Ratio of complete to incomplete length: {(complete_avg / incomplete_avg):,.2f}x\n\n")

def main() -> None:
    """Main function to process images and find patterns."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan base64-encoded images for patterns')
    parser.add_argument('path', help='Path to image file or directory')
    args = parser.parse_args()
    
    target_path = Path(args.path)
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        return
    
    # Setup output directory with source directory structure
    timestamp = datetime.now().strftime("%B_%d_%Y_%H-%M")
    
    if target_path.is_file():
        # For single file, use its parent directory name
        source_dir_name = f"{target_path.parent.parent.name}_{target_path.parent.name}"
    else:
        # For directory, use parent and directory name
        source_dir_name = f"{target_path.parent.name}_{target_path.name}"
    
    # Create output directory structure: scan_results/source_dir/scan_timestamp
    output_dir = Path("scan_results") / source_dir_name / f"scan_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Saving results to: {output_dir}")
    
    # Initialize scanner and process images
    scanner = Base64PatternScanner()
    all_results = []
    total_start = time.time()
    
    for image_path in scanner.get_image_files(target_path):
        try:
            image_start = time.time()
            result = scanner.scan_image(image_path)
            scanner.save_results(output_dir, result)
            all_results.append(result)
            print(f"Processed in {time.time() - image_start:.2f} seconds")
        except Exception as e:
            print(f"Error processing {image_path}: {e}")
    
    # Write final summary
    scanner.write_final_summary(output_dir, all_results)
    print(f"\nTotal processing time: {time.time() - total_start:.2f} seconds")
    print(f"Results saved to: {output_dir}")

if __name__ == "__main__":
    main() 