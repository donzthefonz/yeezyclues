from typing import Tuple, List, Optional, Set
from PIL import Image
import base64
import io
import random
import string
import sys
import os

# Define the contract words to be used
CONTRACT_WORDS: Set[str] = {
    '4NBT', 'F8PF', 'LH4O', 'LFNW', 'F3KN', 
    'V46F', 'Y9I5', 'OXJD', 'XFFC', 'ETXR', 'PUMP'
}

def embed_hidden_code(
    image_path: str,
    hidden_codes: List[str],
    output_path: str
) -> bool:
    """
    Embeds 4-character contract codes into an image's data in a way that they appear in base64
    encoding but don't affect the visual appearance.

    Args:
        image_path: Path to the input image
        hidden_codes: List of 4-character contract codes to hide
        output_path: Path where to save the modified image

    Returns:
        bool: True if successful, False otherwise

    Raises:
        ValueError: If codes are not 4 characters or if image cannot be processed
    """
    try:
        if not os.path.exists(image_path):
            raise ValueError(f"Input image not found: {image_path}")

        # Validate input codes
        for code in hidden_codes:
            if not (len(code) == 4 and code.isalnum()):
                raise ValueError("Each code must be exactly 4 alphanumeric characters")
            if code not in CONTRACT_WORDS:
                raise ValueError(f"Code {code} is not in the valid contract words list")

        # Open and convert image to bytes
        with Image.open(image_path) as img:
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format=img.format)
            img_bytes = img_byte_arr.getvalue()

        # Convert to base64
        b64_data = base64.b64encode(img_bytes).decode('utf-8')
        
        # Find safe positions to insert codes
        # We'll look for patterns that won't affect the image data
        positions = []
        for i in range(len(b64_data) - 4):
            if all(c in string.ascii_letters + string.digits + '+/' for c in b64_data[i:i+4]):
                positions.append(i)

        if len(positions) < len(hidden_codes):
            raise ValueError("Not enough safe positions to embed all codes")

        # Randomly select positions for each code
        selected_positions = random.sample(positions, len(hidden_codes))
        
        # Create modified base64 string
        modified_b64 = list(b64_data)
        for pos, code in zip(selected_positions, hidden_codes):
            modified_b64[pos:pos+4] = code

        # Convert back to bytes and save
        modified_bytes = base64.b64decode(''.join(modified_b64))
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(modified_bytes)

        return True

    except Exception as e:
        print(f"Error during embedding: {str(e)}")
        return False

def extract_hidden_codes(image_path: str) -> List[str]:
    """
    Extracts potential contract codes from an image's base64 representation.

    Args:
        image_path: Path to the image to analyze

    Returns:
        List[str]: List of found valid contract codes

    Raises:
        ValueError: If image cannot be processed
    """
    try:
        if not os.path.exists(image_path):
            raise ValueError(f"Input image not found: {image_path}")

        # Read image and convert to base64
        with open(image_path, 'rb') as f:
            img_data = f.read()
        
        b64_data = base64.b64encode(img_data).decode('utf-8')
        
        # Find all valid contract codes
        codes = []
        for i in range(len(b64_data) - 3):
            segment = b64_data[i:i+4]
            if segment in CONTRACT_WORDS:
                codes.append(segment)
        
        return codes

    except Exception as e:
        print(f"Error during extraction: {str(e)}")
        return []

def main():
    """
    Example usage of the steganography functions.
    """
    if len(sys.argv) < 2:
        print("Usage: python stego_b64.py <input_image_path> [output_image_path]")
        sys.exit(1)

    input_image = sys.argv[1]
    # Generate output filename based on input if not provided
    output_image = sys.argv[2] if len(sys.argv) > 2 else f"encoded_{os.path.basename(input_image)}"
    
    # Example contract words to hide - you can modify this list
    hidden_codes = ['4NBT', 'F8PF', 'LH4O', 'LFNW', 'F3KN', 'V46F', 
        'Y9I5', 'OXJD', 'XFFC', 'ETXR', 'PUMP']
    
    print(f"Processing image: {input_image}")
    print(f"Output will be saved as: {output_image}")
    print(f"Embedding codes: {hidden_codes}")
    
    success = embed_hidden_code(input_image, hidden_codes, output_image)
    if success:
        print("Contract codes successfully embedded!")
        
        # Extract and verify
        found_codes = extract_hidden_codes(output_image)
        print("Found contract codes:", found_codes)
    else:
        print("Failed to embed codes")
        sys.exit(1)

if __name__ == "__main__":
    main() 