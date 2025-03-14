# Stego Tools Collection

A collection of tools for web scraping, image analysis, and steganography detection.

## Tools Included

1. **Yews Image Scraper** (`yews_image_scraper.py`)
   - Scrapes images from yews.live
   - Handles dynamic content loading
   - Saves images to organized directories

2. **Image to Base64 Scanner** (`image_base64_scanner.py`)
   - Converts and analyzes images for base64 encoded content
   - Performs pattern matching and analysis

3. **Stego Check** (`stego_check.py`)
   - Comprehensive steganography detection tool
   - Multiple analysis methods including:
     - Metadata scanning
     - Raw byte analysis
     - Binary pattern detection
     - Multi-bit LSB extraction
     - Per-channel analysis
     - Binwalk integration
     - ICC profile scanning

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- binwalk (optional, for advanced file analysis)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/donzthefonz/yeezyclues
   cd yeezyclues
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Install Playwright browsers (required for web scraping):
   ```bash
   playwright install
   ```

5. (Optional) Install binwalk for advanced file analysis:
   ```bash
   # On macOS:
   brew install binwalk
   # On Ubuntu/Debian:
   sudo apt-get install binwalk
   ```

## Usage

### Yews Image Scraper

```bash
python yews_image_scraper.py
```

Images will be saved to the `yews_images` directory by default.

### Image to Base64 Scanner

```bash
python image_base64_scanner.py <image_file or directory> [--include-words] [--max-word-length N]
```

Options:
- `--include-words`: Include dictionary word search in addition to pattern matching (slower)
- `--max-word-length N`: Set maximum word length for word search when using --include-words (default: 6)

Examples:
```bash
# Default scan (patterns only, fastest)
python image_base64_scanner.py path/to/image.jpg

# Include dictionary word search up to 6 letters
python image_base64_scanner.py path/to/image.jpg --include-words

# Include dictionary word search up to 10 letters
python image_base64_scanner.py path/to/image.jpg --include-words --max-word-length 10

# Scan all images in a directory (patterns only)
python image_base64_scanner.py path/to/directory
```

The tool will:
- Convert images to base64
- Search for special patterns (high and low significance)
- Optionally search for dictionary words (with --include-words flag)
- Generate detailed reports in the scan_results directory
- Create a final summary of findings

Special patterns are categorized into:
- High Significance: Critical identifiers (4NBT, YEEZY, etc.) and steganography markers
- Low Significance: Related terms and common encoding patterns

By default, the tool runs in pattern-matching only mode for faster processing. Use --include-words if you want to also search for dictionary words.

### Stego Check

```bash
python stego_check.py <image_file or directory>
```

The tool will perform multiple analyses:
- Metadata analysis
- Raw byte scanning
- Binary pattern detection
- LSB steganography detection (1-bit, 2-bit, and 4-bit)
- Color channel analysis
- Hidden file detection (requires binwalk)
- ICC profile analysis
- Hidden zip detection

Results will be displayed in the terminal, with any suspicious findings clearly marked.

## End-to-End Workflow

Here's how to use the tools together for a complete analysis:

1. First, scrape images from yews.live:
   ```bash
   # Scrape images from yews.news (default)
   python yews_image_scraper.py
    
    or

   # Scrape images from yews.live
   python yews_image_scraper.py --domain yews.live
   ```
   This will download images to the `yews_images` directory.

2. Run the base64 scanner on all downloaded images:
   ```bash
   python image_base64_scanner.py yews_images

   or
    # List all found words within the images (slow)
   python image_base64_scanner.py yews_images --include-words
   ```
   This will analyze all images in the yews_images directory for potential encoded content.

3. Check the results:
   - Navigate to the `scan_results` directory
   - Review the generated reports for each image
   - Look for any "High Significance" matches in the summary
   - Pay special attention to files that show multiple pattern matches

If you find suspicious images, you can perform deeper analysis:
```bash
python stego_check.py yews_images/suspicious_image.jpg
```

## Output Directories

- `yews_images/`: Contains scraped images
- `scan_results/`: Contains analysis results and reports

## Notes

- Some features of the stego check tool require binwalk to be installed for full functionality
- The scraper respects robots.txt and implements reasonable delays between requests
- For large images, the analysis tools may take several minutes to complete

## Error Handling

If you encounter any issues:
1. Ensure all dependencies are correctly installed
2. Check that input files exist and are accessible
3. Verify you have appropriate permissions for output directories

## License

[Your License Information Here]

## Contributing

[Your Contribution Guidelines Here] 