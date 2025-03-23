#!/usr/bin/env python3

from typing import List
import json
from pathlib import Path


def get_image_titles(metadata_dir: str) -> List[str]:
    """
    Extract all image titles from JSON metadata files in the specified directory.
    
    Args:
        metadata_dir: Path to directory containing JSON metadata files
        
    Returns:
        List of unique, non-empty image titles
    """
    titles = set()
    
    # Recursively find all JSON files in the directory
    for json_file in Path(metadata_dir).rglob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Extract titles from images array
            for image in data.get('images', []):
                title = image.get('title', '').strip()
                if title:  # Only add non-empty titles
                    titles.add(title)
                    
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            
    return sorted(list(titles))


def format_titles(titles: List[str]) -> str:
    """
    Format list of titles into a comma-separated string.
    
    Args:
        titles: List of titles to format
        
    Returns:
        Formatted string with titles separated by commas
    """
    return ", ".join(titles)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Extract image titles from metadata files')
    parser.add_argument('metadata_dir', help='Directory containing JSON metadata files')
    parser.add_argument('--output', '-o', help='Output file (optional)')
    
    args = parser.parse_args()
    
    titles = get_image_titles(args.metadata_dir)
    formatted_titles = format_titles(titles)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(formatted_titles)
        print(f"Titles written to {args.output}")
    else:
        print(formatted_titles)