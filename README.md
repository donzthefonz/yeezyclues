# Stego Tools Collection

A collection of tools for web scraping, image analysis, and steganography detection.

## Tools Included

1. **Yews Image Scraper** (`yews_image_scraper.py`)
   - Scrapes images from specified web sources
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
python image_base64_scanner.py <image_file>
```

### Stego Check

```bash
python stego_check.py <image_file>
```

The tool will perform multiple analyses:
- Metadata analysis
- Raw byte scanning
- Binary pattern detection
- LSB steganography detection (1-bit, 2-bit, and 4-bit)
- Color channel analysis
- Hidden file detection (requires binwalk)
- ICC profile analysis

Results will be displayed in the terminal, with any suspicious findings clearly marked.

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