import os
import sys
from pathlib import Path
from typing import List, Optional, Dict
import requests
from datetime import datetime
import time
import argparse
from tqdm import tqdm  # For progress bars
import random
import json

def setup_download_directory() -> Path:
    """
    Create and return path to a timestamped download directory.
    
    Returns:
        Path: Directory where downloaded images will be stored
    """
    readable_date = datetime.now().strftime("%B_%d_%Y_%H-%M")
    download_dir = Path("downloaded_images") / f"batch_{readable_date}"
    download_dir.mkdir(parents=True, exist_ok=True)
    return download_dir

def get_wallhaven_images(
    api_key: Optional[str],
    query: str = "",
    categories: str = "111",  # General, Anime, People
    purity: str = "100",      # SFW only by default
    resolutions: List[str] = ["3840x2160"],  # 4K by default
    page: int = 1
) -> Optional[Dict]:
    """
    Search for images on Wallhaven using their API.
    
    Args:
        api_key: Optional Wallhaven API key
        query: Search query string
        categories: Category flags (general,anime,people)
        purity: Purity flags (sfw,sketchy,nsfw)
        resolutions: List of desired resolutions
        page: Page number for results
        
    Returns:
        Optional[Dict]: Search results if successful, None if failed
    """
    try:
        params = {
            "q": query,
            "categories": categories,
            "purity": purity,
            "resolutions": ",".join(resolutions),
            "page": page,
            "sorting": "random"
        }
        
        headers = {}
        if api_key:
            headers["X-API-Key"] = api_key
            
        url = "https://wallhaven.cc/api/v1/search"
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"\nError fetching wallpapers: {e}")
        return None

def download_image(url: str, save_path: Path, timeout: int = 30) -> bool:
    """
    Download an image from a URL and save it to the specified path.
    
    Args:
        url: URL of the image to download
        save_path: Path where the image should be saved
        timeout: Timeout in seconds for the download request
        
    Returns:
        bool: True if download was successful, False otherwise
    """
    try:
        response = requests.get(url, timeout=timeout, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        
        with open(save_path, 'wb') as f:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc=save_path.name) as pbar:
                for chunk in response.iter_content(chunk_size=block_size):
                    f.write(chunk)
                    pbar.update(len(chunk))
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def download_wallhaven_images(
    count: int,
    api_key: Optional[str] = None,
    query: str = "",
    categories: str = "111",
    purity: str = "100",
    width: int = 3840,
    height: int = 2160,
    max_retries: int = 5
) -> List[Path]:
    """
    Download wallpapers from Wallhaven.
    
    Args:
        count: Number of images to download
        api_key: Optional Wallhaven API key
        query: Search query string
        categories: Category flags (general,anime,people)
        purity: Purity flags (sfw,sketchy,nsfw)
        width: Desired width in pixels
        height: Desired height in pixels
        max_retries: Maximum number of retries per image
        
    Returns:
        List[Path]: Paths to successfully downloaded images
    """
    download_dir = setup_download_directory()
    downloaded_files: List[Path] = []
    resolution = f"{width}x{height}"
    page = 1
    
    with tqdm(total=count, desc="Downloading wallpapers") as pbar:
        while len(downloaded_files) < count:
            # Get a page of search results
            results = get_wallhaven_images(
                api_key=api_key,
                query=query,
                categories=categories,
                purity=purity,
                resolutions=[resolution],
                page=page
            )
            
            if not results or not results.get('data'):
                print("\nNo more results found")
                break
                
            # Try to download each wallpaper
            for wallpaper in results['data']:
                if len(downloaded_files) >= count:
                    break
                    
                try:
                    # Get the direct image URL
                    image_url = wallpaper['path']
                    
                    # Create filename using wallpaper ID and resolution
                    filename = f"wallhaven_{wallpaper['id']}_{resolution}.{image_url.split('.')[-1]}"
                    save_path = download_dir / filename
                    
                    if download_image(image_url, save_path):
                        downloaded_files.append(save_path)
                        pbar.update(1)
                    
                    # Small delay to be nice to the server
                    time.sleep(0.5)
                        
                except Exception as e:
                    print(f"\nError: {e}")
                    time.sleep(1)
            
            page += 1
            if page > 10:  # Limit pages to avoid too many requests
                print("\nReached maximum page limit")
                break
    
    return downloaded_files

def main() -> None:
    """
    Main function to handle command line arguments and download images.
    """
    parser = argparse.ArgumentParser(description='Download wallpapers from Wallhaven')
    parser.add_argument('--count', type=int, default=10,
                       help='Number of wallpapers to download (default: 10)')
    parser.add_argument('--width', type=int, default=3840,
                       help='Image width in pixels (default: 3840 for 4K)')
    parser.add_argument('--height', type=int, default=2160,
                       help='Image height in pixels (default: 2160 for 4K)')
    parser.add_argument('--query', type=str, default="",
                       help='Search query (default: "")')
    parser.add_argument('--categories', type=str, default="111",
                       help='Category flags - general,anime,people (default: 111)')
    parser.add_argument('--purity', type=str, default="100",
                       help='Purity flags - sfw,sketchy,nsfw (default: 100 for SFW only)')
    parser.add_argument('--api-key', type=str,
                       help='Wallhaven API key (optional)')
    parser.add_argument('--max-retries', type=int, default=5,
                       help='Maximum retries per image (default: 5)')
    
    args = parser.parse_args()
    
    try:
        start_time = time.time()
        downloaded_files = download_wallhaven_images(
            count=args.count,
            api_key=args.api_key,
            query=args.query,
            categories=args.categories,
            purity=args.purity,
            width=args.width,
            height=args.height,
            max_retries=args.max_retries
        )
        
        # Print summary
        print(f"\nDownload Summary:")
        print(f"Successfully downloaded: {len(downloaded_files)} wallpapers")
        if downloaded_files:
            print(f"Download directory: {downloaded_files[0].parent}")
            print("Files:")
            for file in downloaded_files:
                print(f"  - {file.name}")
        print(f"Time taken: {time.time() - start_time:.2f} seconds")
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 