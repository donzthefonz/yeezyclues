import os
import sys
from pathlib import Path
from typing import List, Dict, Optional, Any
import requests
from datetime import datetime
import time
import argparse
from tqdm import tqdm
import json

def setup_download_directory() -> Path:
    """
    Create and return path to a timestamped download directory for Blake artwork.
    
    Returns:
        Path: Directory where downloaded images will be stored
    """
    readable_date = datetime.now().strftime("%B_%d_%Y_%H-%M")
    download_dir = Path("blake_artwork") / f"batch_{readable_date}"
    download_dir.mkdir(parents=True, exist_ok=True)
    return download_dir

def get_blake_artworks(page: int = 1, limit: int = 100) -> Optional[Dict[str, Any]]:
    """
    Search for William Blake artworks in the Art Institute of Chicago API.
    
    Args:
        page: Page number for results
        limit: Number of results per page
        
    Returns:
        Optional[Dict[str, Any]]: Search results if successful, None if failed
    """
    try:
        params = {
            "q": "William Blake",
            "limit": limit,
            "page": page,
            "fields": "id,title,image_id,date_display,medium_display",
            "query[term][is_public_domain]": True
        }
        
        url = "https://api.artic.edu/api/v1/artworks/search"
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"\nError fetching artworks: {e}")
        return None

def get_image_url(image_id: str, size: str = "full") -> str:
    """
    Generate the IIIF image URL for downloading.
    
    Args:
        image_id: The image identifier
        size: Size specification for the image
        
    Returns:
        str: Complete URL for downloading the image
    """
    return f"https://www.artic.edu/iiif/2/{image_id}/full/{size}/0/default.jpg"

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
                    
        # Also save metadata in a companion JSON file
        metadata_path = save_path.with_suffix('.json')
        with open(metadata_path, 'w') as f:
            json.dump({
                'url': url,
                'download_date': datetime.now().isoformat()
            }, f, indent=2)
            
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def download_blake_artworks(max_images: int = 100, size: str = "full") -> List[Path]:
    """
    Download William Blake artworks from the Art Institute of Chicago.
    
    Args:
        max_images: Maximum number of images to download
        size: Size specification for images ('full' for maximum quality)
        
    Returns:
        List[Path]: Paths to successfully downloaded images
    """
    download_dir = setup_download_directory()
    downloaded_files: List[Path] = []
    page = 1
    
    with tqdm(total=max_images, desc="Downloading Blake artworks") as pbar:
        while len(downloaded_files) < max_images:
            results = get_blake_artworks(page=page)
            
            if not results or not results.get('data'):
                print("\nNo more results found")
                break
            
            for artwork in results['data']:
                if len(downloaded_files) >= max_images:
                    break
                
                try:
                    if not artwork.get('image_id'):
                        continue
                        
                    image_url = get_image_url(artwork['image_id'], size)
                    
                    # Create filename using artwork ID and title
                    safe_title = "".join(c for c in artwork['title'] if c.isalnum() or c in (' ', '-', '_'))[:50]
                    filename = f"blake_{artwork['id']}_{safe_title}.jpg"
                    save_path = download_dir / filename
                    
                    if download_image(image_url, save_path):
                        # Save artwork metadata
                        metadata_path = save_path.with_suffix('.json')
                        with open(metadata_path, 'w') as f:
                            json.dump({
                                'id': artwork['id'],
                                'title': artwork['title'],
                                'date': artwork['date_display'],
                                'medium': artwork['medium_display'],
                                'download_date': datetime.now().isoformat()
                            }, f, indent=2)
                            
                        downloaded_files.append(save_path)
                        pbar.update(1)
                    
                    time.sleep(0.5)  # Be nice to the API
                        
                except Exception as e:
                    print(f"\nError processing artwork: {e}")
                    time.sleep(1)
            
            page += 1
    
    return downloaded_files

def main() -> None:
    """
    Main function to handle command line arguments and download Blake artworks.
    """
    parser = argparse.ArgumentParser(description='Download William Blake artworks from the Art Institute of Chicago')
    parser.add_argument('--max-images', type=int, default=100,
                       help='Maximum number of images to download (default: 100)')
    parser.add_argument('--size', type=str, default="full",
                       help='Image size (default: "full" for maximum quality)')
    
    args = parser.parse_args()
    
    try:
        start_time = time.time()
        downloaded_files = download_blake_artworks(
            max_images=args.max_images,
            size=args.size
        )
        
        # Print summary
        print(f"\nDownload Summary:")
        print(f"Successfully downloaded: {len(downloaded_files)} Blake artworks")
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