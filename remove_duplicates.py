#!/usr/bin/env python3

import hashlib
import os
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict


def calculate_file_hash(filepath: Path) -> str:
    """
    Calculate SHA-256 hash of a file.
    
    Args:
        filepath: Path object pointing to the file to hash
        
    Returns:
        str: Hexadecimal representation of the file's SHA-256 hash
    """
    sha256_hash = hashlib.sha256()
    
    with open(filepath, "rb") as f:
        # Read the file in chunks to handle large files efficiently
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()


def find_duplicate_files(directory: str) -> Dict[str, List[Path]]:
    """
    Find duplicate files in the specified directory.
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        Dict mapping file hashes to lists of paths with identical content
    """
    hash_map: Dict[str, List[Path]] = defaultdict(list)
    scanned_files: Set[Path] = set()
    
    # Convert directory to Path object
    dir_path = Path(directory)
    
    # Recursively scan all files in directory
    for filepath in dir_path.rglob("*"):
        if filepath.is_file() and filepath not in scanned_files:
            file_hash = calculate_file_hash(filepath)
            hash_map[file_hash].append(filepath)
            scanned_files.add(filepath)
    
    # Filter out unique files (those without duplicates)
    return {k: v for k, v in hash_map.items() if len(v) > 1}


def remove_duplicates(directory: str, keep_newest: bool = True) -> None:
    """
    Remove duplicate files from the specified directory.
    
    Args:
        directory: Path to the directory to clean
        keep_newest: If True, keeps the newest file among duplicates.
                    If False, keeps the oldest file.
    """
    duplicates = find_duplicate_files(directory)
    
    if not duplicates:
        print("No duplicate files found.")
        return
    
    print(f"Found {sum(len(files) - 1 for files in duplicates.values())} duplicate files:")
    
    for file_hash, file_list in duplicates.items():
        # Sort files by modification time
        sorted_files = sorted(file_list, key=lambda x: x.stat().st_mtime,
                            reverse=keep_newest)
        
        # Keep the first file (newest or oldest depending on keep_newest)
        keeper = sorted_files[0]
        to_remove = sorted_files[1:]
        
        print(f"\nKeeping: {keeper}")
        print("Removing duplicates:")
        for file_path in to_remove:
            print(f"  - {file_path}")
            try:
                os.remove(file_path)
            except OSError as e:
                print(f"Error removing {file_path}: {e}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Find and remove duplicate files in a directory"
    )
    parser.add_argument(
        "directory",
        help="Directory to scan for duplicates"
    )
    parser.add_argument(
        "--keep-oldest",
        action="store_true",
        help="Keep oldest file instead of newest (default: keep newest)"
    )
    
    args = parser.parse_args()
    remove_duplicates(args.directory, keep_newest=not args.keep_oldest) 