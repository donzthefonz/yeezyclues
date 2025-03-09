import os
import sys
from pathlib import Path
from typing import List
import requests
from datetime import datetime
import time
import argparse
from tqdm import tqdm  # For progress bars
import random

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

def download_image(url: str, save_path: Path, timeout: int = 10) -> bool:
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
        
        with open(save_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def download_random_images(
    count: int,
    width: int = 1920,
    height: int = 1080,
    grayscale: bool = False
) -> List[Path]:
    """
    Download random images from Lorem Picsum.
    
    Args:
        count: Number of images to download
        width: Image width in pixels
        height: Image height in pixels
        grayscale: Whether to get grayscale images
        
    Returns:
        List[Path]: Paths to successfully downloaded images
    """
    download_dir = setup_download_directory()
    downloaded_files: List[Path] = []
    
    with tqdm(total=count, desc="Downloading images") as pbar:
        for i in range(count):
            try:
                # Generate random seed for variety
                seed = random.randint(1, 1000)
                
                # Construct URL with parameters
                url = f"https://picsum.photos/seed/{seed}/{width}/{height}"
                if grayscale:
                    url += "?grayscale"
                
                # Create filename
                filename = f"random_{seed}_{width}x{height}.jpg"
                save_path = download_dir / filename
                
                if download_image(url, save_path):
                    downloaded_files.append(save_path)
                    pbar.update(1)
                
                # Small delay to be nice to the server
                time.sleep(0.1)
                    
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(1)  # Wait longer on error
    
    return downloaded_files

def main() -> None:
    """
    Main function to handle command line arguments and download images.
    """
    parser = argparse.ArgumentParser(description='Download random JPEG images from Lorem Picsum')
    parser.add_argument('--count', type=int, default=10,
                       help='Number of images to download (default: 10)')
    parser.add_argument('--width', type=int, default=1920,
                       help='Image width in pixels (default: 1920)')
    parser.add_argument('--height', type=int, default=1080,
                       help='Image height in pixels (default: 1080)')
    parser.add_argument('--grayscale', action='store_true',
                       help='Download grayscale images')
    
    args = parser.parse_args()
    
    try:
        start_time = time.time()
        downloaded_files = download_random_images(
            count=args.count,
            width=args.width,
            height=args.height,
            grayscale=args.grayscale
        )
        
        # Print summary
        print(f"\nDownload Summary:")
        print(f"Successfully downloaded: {len(downloaded_files)} images")
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