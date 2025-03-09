#!/usr/bin/env python3

from typing import List, Optional, Set
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
from datetime import datetime, timedelta
import time
import re
import asyncio
from playwright.async_api import async_playwright, Page, TimeoutError

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Changed to DEBUG level
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class YewsImageScraper:
    """A scraper class to download images from the YEWS website."""
    
    def __init__(self, base_url: str, output_dir: str = "yews_images"):
        """
        Initialize the scraper with base URL and output directory.
        
        Args:
            base_url: The base URL of the YEWS website
            output_dir: Directory where images will be saved
        """
        self.base_url = base_url.rstrip('/')
        self.output_dir = output_dir
        self.session = requests.Session()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.visited_urls: Set[str] = set()
        
    def setup_output_directory(self) -> None:
        """Create the output directory if it doesn't exist."""
        os.makedirs(self.output_dir, exist_ok=True)

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

    def extract_image_urls(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract image URLs from an article page.
        
        Args:
            html_content: HTML content of the article page
            base_url: Base URL of the article
            
        Returns:
            List of image URLs
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        image_urls = []
        
        # Debug: Log all img tags found
        all_images = soup.find_all('img')
        logger.debug(f"Found {len(all_images)} img tags on the page")
        
        # Find all images
        for img in all_images:
            src = img.get('src')
            if src:
                absolute_url = urljoin(base_url, src)
                image_urls.append(absolute_url)
                logger.debug(f"Found image URL: {absolute_url}")
        
        # Also look for background images in style attributes
        elements_with_style = soup.find_all(lambda tag: tag.get('style'))
        logger.debug(f"Found {len(elements_with_style)} elements with style attributes")
        
        for element in elements_with_style:
            style = element.get('style', '')
            if 'background-image' in style and 'url(' in style:
                url = style.split('url(')[1].split(')')[0].strip("'").strip('"')
                absolute_url = urljoin(base_url, url)
                image_urls.append(absolute_url)
                logger.debug(f"Found background image URL: {absolute_url}")
                
        return list(set(image_urls))

    def download_image(self, url: str, edition_date: str) -> None:
        """
        Download an image from the given URL.
        
        Args:
            url: URL of the image to download
            edition_date: Date of the edition (for filename)
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
            
            # Generate filename with edition date
            filename = f"yews_{edition_date}_{clean_filename}"
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
            # Click the time button
            if not await self.click_time_button(page, time_text):
                logger.error(f"Failed to click {time_text} button")
                return
                
            # Take a screenshot after clicking the time button
            await page.screenshot(path=f"debug_screenshot_{time_text}.png")
            
            # Expand all articles
            await self.expand_all_articles(page)
            
            # Take another screenshot after expanding articles
            await page.screenshot(path=f"debug_screenshot_{time_text}_expanded.png")
            
            # Get the page content and extract images
            content = await page.content()
            image_urls = self.extract_image_urls(content, page.url)
            
            # Download images
            for image_url in image_urls:
                self.download_image(image_url, time_text)
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

async def main() -> None:
    """Main function to run the scraper."""
    scraper = YewsImageScraper("https://www.yews.live")
    await scraper.run()

if __name__ == "__main__":
    asyncio.run(main()) 