import argparse
from pathlib import Path
import base64
import re
from typing import Optional, Tuple
import sys

def extract_mime_and_data(base64_string: str) -> Tuple[Optional[str], str]:
    """
    Extract MIME type and actual base64 data from a data URI string.
    
    Args:
        base64_string: The base64 string, possibly with data URI prefix
        
    Returns:
        Tuple of (mime_type, base64_data) where mime_type may be None
    """
    # Check for data URI format
    data_uri_pattern = r'^data:([^;]+);base64,(.+)$'
    match = re.match(data_uri_pattern, base64_string.strip())
    
    if match:
        return match.group(1), match.group(2)
    return None, base64_string.strip()

def get_extension_from_mime(mime_type: Optional[str]) -> str:
    """
    Get the appropriate file extension based on MIME type.
    
    Args:
        mime_type: MIME type string or None
        
    Returns:
        File extension including the dot
    """
    if not mime_type:
        return '.png'  # Default to PNG if no MIME type
        
    mime_to_ext = {
        'image/png': '.png',
        'image/jpeg': '.jpg',
        'image/gif': '.gif',
        'image/bmp': '.bmp',
        'image/webp': '.webp'
    }
    return mime_to_ext.get(mime_type.lower(), '.png')

def base64_to_image(base64_string: str, output_path: Optional[Path] = None) -> Path:
    """
    Convert a base64 string back to an image file.
    
    Args:
        base64_string: The base64 string to convert
        output_path: Optional specific output path, will auto-generate if not provided
        
    Returns:
        Path to the saved image file
    """
    # Extract MIME type and base64 data
    mime_type, base64_data = extract_mime_and_data(base64_string)
    
    try:
        # Decode the base64 data
        image_data = base64.b64decode(base64_data)
        
        # Generate output path if not provided
        if output_path is None:
            ext = get_extension_from_mime(mime_type)
            output_path = Path(f"decoded_image{ext}")
        
        # Ensure the output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write the image file
        with open(output_path, 'wb') as f:
            f.write(image_data)
            
        print(f"Successfully saved image to: {output_path}")
        return output_path
        
    except Exception as e:
        print(f"Error converting base64 to image: {e}")
        sys.exit(1)

def main() -> None:
    """
    Main function to handle command line arguments and convert base64 to image.
    """
    parser = argparse.ArgumentParser(description='Convert base64 string to image file')
    parser.add_argument('input', help='Path to file containing base64 string or the base64 string itself')
    parser.add_argument('--output', '-o', type=str, help='Output image path (optional)')
    
    args = parser.parse_args()
    
    # Check if input is a file path or direct base64 string
    if Path(args.input).exists():
        print(f"Reading base64 from file: {args.input}")
        with open(args.input, 'r') as f:
            base64_string = f.read()
    else:
        base64_string = args.input
    
    # Setup output path if provided
    output_path = Path(args.output) if args.output else None
    
    # Convert and save the image
    base64_to_image(base64_string, output_path)

if __name__ == "__main__":
    main() 