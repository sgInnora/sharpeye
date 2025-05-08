#!/usr/bin/env python3
"""
Create a square version of the SharpEye logo for GitHub
"""

import os
from PIL import Image

def create_square_logo(input_path='logo.png', output_path='logo_square.png', size=(512, 512)):
    """
    Create a square version of the logo with padding
    
    Args:
        input_path: Path to the input logo
        output_path: Path to save the square logo
        size: Size of the square logo
    """
    # Load the original logo
    img = Image.open(input_path)
    
    # Create a new image with transparent background
    square_img = Image.new('RGBA', size, (0, 0, 0, 0))
    
    # Calculate the position to center the logo
    pos = ((size[0] - img.width) // 2, (size[1] - img.height) // 2)
    
    # Paste the logo onto the new image
    square_img.paste(img, pos, img)
    
    # Save the new image
    square_img.save(output_path)
    print(f"Square logo saved to {output_path}")

if __name__ == "__main__":
    # Get the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Set the input and output paths
    input_path = os.path.join(script_dir, 'logo.png')
    output_path = os.path.join(script_dir, 'logo_square.png')
    
    # Create the square logo
    create_square_logo(input_path=input_path, output_path=output_path)