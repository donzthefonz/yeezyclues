#!/usr/bin/env python3

from typing import List, Optional, Set, Literal, Union, Dict
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from datetime import datetime, timedelta
import time
import re
import asyncio
import json
from dataclasses import dataclass, asdict
from playwright.async_api import async_playwright, Page, TimeoutError
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG level
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Article:
    """Data class to store article information."""
    title: str
    text: str
    images: List[Dict[str, str]]  # List of dicts with 'url' and 'alt' keys
    time_section: str
    date: str

class YewsImageScraper:
    """A scraper class to download images from YEWS websites, including archived versions."""
    
    def __init__(self, source: Union[Literal["yews.news", "yews.live"], str] = "yews.news", output_base_dir: str = "yews_images"):
        """
        Initialize the scraper with source URL and output directory.
        
        Args:
            source: Either a domain ("yews.news" or "yews.live") or a full archive.org URL. Defaults to "yews.news"
            output_base_dir: Base directory where date-specific folders will be created
        """
        self.is_archive = source.startswith("http")
        if self.is_archive:
            self.base_url = source
            # Extract domain and timestamp from archive URL
            match = re.search(r'web/(\d+)/(?:https://www\.)?([^/]+)', source)
            if match:
                self.timestamp, self.domain = match.groups()
            else:
                raise ValueError("Invalid archive.org URL format")
        else:
            self.domain = source
            self.base_url = f"https://www.{source}"
            self.timestamp = None
            
        self.output_base_dir = output_base_dir
        self.output_dir = self._get_dated_output_dir()
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.visited_urls: Set[str] = set()
        self.articles: List[Article] = []

    def _get_dated_output_dir(self) -> str:
        """
        Create and return a dated output directory path.
        
        Returns:
            Path to the dated output directory
        """
        if self.is_archive:
            # Use the timestamp from archive URL (YYYYMMDDHHMMSS format)
            date_str = f"{self.timestamp[:4]}-{self.timestamp[4:6]}-{self.timestamp[6:8]}"
            domain_name = f"archive_{self.domain.replace('.', '_')}"
        else:
            date_str = datetime.now().strftime("%Y-%m-%d")
            domain_name = self.domain.replace(".", "_")
            
        dated_dir = os.path.join(self.output_base_dir, domain_name, date_str)
        return dated_dir

    def setup_output_directory(self) -> None:
        """Create the dated output directory and metadata subdirectory."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "metadata"), exist_ok=True)
        logger.info(f"Created output directories: {self.output_dir}")

    async def click_time_button(self, page: Page, time_text: str) -> bool:
        """
        Click a time button (10AM, 3PM, 8PM) on the main page.
        
        Args:
            page: Playwright page object
            time_text: The text of the time button to click
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Wait for the button to be visible
            button = await page.wait_for_selector(f"text={time_text}", timeout=5000)
            if button:
                logger.debug(f"Found {time_text} button")
                await button.click()
                await page.wait_for_timeout(2000)  # Wait for navigation
                return True
            return False
        except TimeoutError:
            logger.warning(f"Could not find {time_text} button")
            return False
        except Exception as e:
            logger.error(f"Error clicking {time_text} button: {e}")
            return False

    async def expand_all_articles(self, page: Page) -> None:
        """
        Expand all article sections on the page.
        
        Args:
            page: Playwright page object
        """
        try:
            # Wait for any dynamic content to load
            await page.wait_for_timeout(2000)
            
            # Debug: Log the page title and URL
            logger.debug(f"Current page title: {await page.title()}")
            logger.debug(f"Current page URL: {page.url}")
            
            # Find all expand buttons
            expand_buttons = await page.query_selector_all('div[role="button"]')
            logger.debug(f"Found {len(expand_buttons)} expand buttons")
            
            # Click each expand button
            for i, button in enumerate(expand_buttons):
                try:
                    if await button.is_visible():
                        # Debug: Log button details
                        button_text = await button.text_content()
                        logger.debug(f"Clicking expand button {i+1} with text: {button_text}")
                        await button.click()
                        await page.wait_for_timeout(1000)  # Increased wait time
                except Exception as e:
                    logger.warning(f"Failed to click expand button {i+1}: {e}")
                    
            # Wait a bit longer after expanding all articles
            await page.wait_for_timeout(2000)
            
        except Exception as e:
            logger.warning(f"Failed to expand articles: {e}")

    def extract_article_data(self, html_content: str, base_url: str, time_section: str) -> List[Article]:
        """
        Extract article data including titles, text, and images from the page.
        
        Args:
            html_content: HTML content of the page
            base_url: Base URL of the article
            time_section: Current time section being processed
            
        Returns:
            List of Article objects
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        articles = []
        
        # Find all article sections
        article_sections = soup.find_all('div', class_=lambda x: x and 'flex flex-col' in x and 'opacity-0' in x)
        
        for section in article_sections:
            # Extract title
            title_elem = section.find('span', class_=lambda x: x and 'cursor-pointer' in x and 'break-words' in x)
            title = title_elem.get_text(strip=True) if title_elem else "Untitled"
            
            # Extract article text
            text_elem = section.find('div', class_=lambda x: x and 'break-words' in x and 'whitespace-pre-line' in x)
            text = text_elem.get_text(strip=True) if text_elem else ""
            
            # Extract images with their metadata
            images = []
            img_elements = section.find_all('img')
            for img in img_elements:
                src = img.get('src')
                if src:
                    if self.is_archive and not src.startswith('http'):
                        if src.startswith('//'):
                            src = f"https:{src}"
                        elif src.startswith('/'):
                            src = f"https://web.archive.org{src}"
                        else:
                            src = urljoin(base_url, src)
                    else:
                        src = urljoin(base_url, src)
                    
                    # Find the image title from the next sibling span
                    img_title = ''
                    title_span = img.find_next('span', class_=lambda x: x and 'text-gray-500' in x and 'break-words' in x)
                    if title_span:
                        img_title = title_span.get_text(strip=True)
                    
                    images.append({
                        'url': src,
                        'alt': img.get('alt', ''),
                        'title': img_title
                    })
            
            # Create Article object
            if images:  # Only add articles that have images
                article = Article(
                    title=title,
                    text=text,
                    images=images,
                    time_section=time_section,
                    date=datetime.now().strftime("%Y-%m-%d") if not self.is_archive else self.timestamp[:8]
                )
                articles.append(article)
        
        return articles

    def save_article_metadata(self, article: Article) -> None:
        """
        Save article metadata to a JSON file.
        
        Args:
            article: Article object containing metadata
        """
        metadata_dir = os.path.join(self.output_dir, "metadata")
        filename = f"article_{article.date}_{article.time_section}_{hash(article.title)}.json"
        filepath = os.path.join(metadata_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(asdict(article), f, ensure_ascii=False, indent=2)
        
        logger.info(f"Saved metadata for article: {article.title}")

    def download_image(self, url: str, edition_date: str, article_title: str, img_metadata: Dict[str, str]) -> None:
        """
        Download an image and save with contextual filename.
        
        Args:
            url: URL of the image to download
            edition_date: Date of the edition
            article_title: Title of the article
            img_metadata: Dictionary containing image metadata
        """
        if url in self.visited_urls:
            logger.debug(f"Skipping already downloaded image: {url}")
            return
            
        try:
            response = self.session.get(url, headers=self.headers)
            response.raise_for_status()
            
            # Extract filename from URL and clean it
            original_filename = url.split('/')[-1].split('?')[0]
            clean_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', original_filename)
            
            # Generate filename with article context
            safe_title = re.sub(r'[^a-zA-Z0-9._-]', '_', article_title)[:50]  # Limit length
            filename = f"yews_{edition_date}_{safe_title}_{clean_filename}"
            filepath = os.path.join(self.output_dir, filename)
            
            with open(filepath, 'wb') as f:
                f.write(response.content)
            logger.info(f"Successfully downloaded: {filename}")
            self.visited_urls.add(url)
            
        except requests.RequestException as e:
            logger.error(f"Failed to download image from {url}: {e}")
        except IOError as e:
            logger.error(f"Failed to save image from {url}: {e}")

    async def process_time_section(self, page: Page, time_text: str) -> None:
        """
        Process a time section (10AM, 3PM, 8PM) of the page.
        
        Args:
            page: Playwright page object
            time_text: The time section to process
        """
        logger.info(f"Processing time section: {time_text}")
        
        try:
            if not await self.click_time_button(page, time_text):
                logger.error(f"Failed to click {time_text} button")
                return
                
            await self.expand_all_articles(page)
            
            content = await page.content()
            articles = self.extract_article_data(content, page.url, time_text)
            
            for article in articles:
                # Save article metadata
                self.save_article_metadata(article)
                
                # Download images with article context
                for img in article.images:
                    self.download_image(
                        img['url'],
                        article.date,
                        article.title,
                        img
                    )
                    await page.wait_for_timeout(500)
                
        except Exception as e:
            logger.error(f"Failed to process time section {time_text}: {e}")

    async def run(self) -> None:
        """Execute the complete scraping process."""
        logger.info("Starting YEWS image scraping process...")
        
        self.setup_output_directory()
        
        async with async_playwright() as p:
            # Launch the browser in non-headless mode with mobile emulation
            browser = await p.chromium.launch(headless=True)
            
            # Create a mobile viewport context
            context = await browser.new_context(
                viewport={'width': 390, 'height': 844},  # iPhone 12 Pro dimensions
                device_scale_factor=2
            )
            
            page = await context.new_page()
            
            try:
                # Navigate to the main page
                await page.goto(self.base_url)
                await page.wait_for_load_state('networkidle')
                
                # Process each time section
                for time_text in ["10AM", "3PM", "8PM"]:
                    await self.process_time_section(page, time_text)
                    await page.goto(self.base_url)  # Go back to main page
                    await page.wait_for_timeout(2000)
                
                # Wait for user input before closing
                input("Press Enter to close the browser...")
                
            finally:
                await browser.close()
            
        logger.info("Image scraping completed!")

async def process_sources(sources: List[str]) -> None:
    """
    Process multiple sources sequentially.
    
    Args:
        sources: List of sources to process (domains or archive.org URLs)
    """
    async with async_playwright() as p:
        # Launch single browser instance for all sources
        browser = await p.chromium.launch(headless=True)
        
        for source in sources:
            source = source.strip()  # Remove any whitespace
            if not source:  # Skip empty lines
                continue
                
            logger.info(f"Processing source: {source}")
            try:
                scraper = YewsImageScraper(source)
                await scraper.run()
            except Exception as e:
                logger.error(f"Failed to process source {source}: {e}")
                continue
            
        await browser.close()

def validate_source(source: str) -> bool:
    """
    Validate a single source.
    
    Args:
        source: Domain or archive.org URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    source = source.strip()
    if source.startswith('http'):
        return source.startswith('https://web.archive.org/web/')
    return source in ['yews.news', 'yews.live']

def read_sources_file(file_path: str) -> List[str]:
    """
    Read sources from a file.
    
    Args:
        file_path: Path to the file containing sources
        
    Returns:
        List of valid sources
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Sources file not found: {file_path}")
        
    with open(file_path, 'r') as f:
        sources = [line.strip() for line in f if line.strip()]
        
    # Validate sources
    valid_sources = []
    for source in sources:
        if validate_source(source):
            valid_sources.append(source)
        else:
            logger.warning(f"Skipping invalid source: {source}")
            
    return valid_sources

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Scrape images from YEWS websites')
    source_group = parser.add_mutually_exclusive_group()  # Remove required=True
    source_group.add_argument('--sources', nargs='+',
                          help='One or more domains (yews.news, yews.live) or archive.org URLs')
    source_group.add_argument('--sources-file',
                          help='Path to file containing list of sources (one per line)')
    
    args = parser.parse_args()
    
    try:
        if args.sources_file:
            sources = read_sources_file(args.sources_file)
        elif args.sources:
            sources = [s.strip() for s in args.sources if s.strip()]
            # Validate sources from command line
            sources = [s for s in sources if validate_source(s)]
        else:
            # Use default source if none provided
            sources = ["yews.news"]
            
        if not sources:
            parser.error("No valid sources provided")
            
        logger.info(f"Processing {len(sources)} sources")
        asyncio.run(process_sources(sources))
        
    except Exception as e:
        logger.error(f"Error: {e}")
        exit(1) 