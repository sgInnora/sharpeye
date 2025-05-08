#!/usr/bin/env python3
"""
Create a new logo for SharpEye in the style of innora.ai
"""

import os
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import io

def create_sharpeye_logo(size=(500, 500), output_path='logo.png'):
    """
    Create a modern, minimalist logo for SharpEye with a color scheme
    matching innora.ai's style
    
    Args:
        size: Tuple of (width, height) for the logo
        output_path: Path to save the logo
    """
    # Create a transparent background
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors from innora.ai
    primary_blue = (51, 102, 255)  # #3366ff
    accent_green = (0, 200, 83)    # #00c853
    dark_navy = (26, 26, 46)       # #1a1a2e
    
    # Calculate center and dimensions
    width, height = size
    center_x, center_y = width // 2, height // 2
    
    # Create a circle background with a gradient-like effect
    radius = min(width, height) // 2 - 20
    
    # Draw a filled circle
    draw.ellipse(
        (center_x - radius, center_y - radius, 
         center_x + radius, center_y + radius),
        fill=dark_navy
    )
    
    # Eye shape (stylized)
    eye_width = radius * 1.4
    eye_height = radius * 0.6
    
    # Draw outer eye shape (ellipse)
    draw.ellipse(
        (center_x - eye_width//2, center_y - eye_height//2,
         center_x + eye_width//2, center_y + eye_height//2),
        outline=primary_blue, width=8
    )
    
    # Draw iris
    iris_radius = eye_height // 2
    draw.ellipse(
        (center_x - iris_radius, center_y - iris_radius,
         center_x + iris_radius, center_y + iris_radius),
        fill=primary_blue
    )
    
    # Draw pupil
    pupil_radius = iris_radius // 2
    draw.ellipse(
        (center_x - pupil_radius, center_y - pupil_radius,
         center_x + pupil_radius, center_y + pupil_radius),
        fill=dark_navy
    )
    
    # Add a highlight
    highlight_radius = pupil_radius // 2
    highlight_offset_x = highlight_radius // 2
    highlight_offset_y = highlight_radius // 2
    draw.ellipse(
        (center_x - highlight_radius + highlight_offset_x, 
         center_y - highlight_radius + highlight_offset_y,
         center_x + highlight_radius + highlight_offset_x, 
         center_y + highlight_radius + highlight_offset_y),
        fill=(255, 255, 255, 180)
    )
    
    # Add a radial line pattern around the eye (representing "sharp" vision)
    num_lines = 8
    outer_radius = radius + 15
    line_width = 4
    
    for i in range(num_lines):
        angle = 2 * np.pi * i / num_lines
        # Calculate endpoints using trigonometry
        x1 = center_x + int(radius * 0.9 * np.cos(angle))
        y1 = center_y + int(radius * 0.9 * np.sin(angle))
        x2 = center_x + int(outer_radius * np.cos(angle))
        y2 = center_y + int(outer_radius * np.sin(angle))
        
        # Draw the line with a gradient-like color
        # Mix between primary blue and accent green based on position
        blend_factor = (i / num_lines) * 0.5 + 0.5  # Map to 0.5-1.0 range
        line_color = (
            int(primary_blue[0] * blend_factor + accent_green[0] * (1 - blend_factor)),
            int(primary_blue[1] * blend_factor + accent_green[1] * (1 - blend_factor)),
            int(primary_blue[2] * blend_factor + accent_green[2] * (1 - blend_factor))
        )
        
        draw.line((x1, y1, x2, y2), fill=line_color, width=line_width)
    
    # Save the image
    img.save(output_path)
    print(f"Logo saved to {output_path}")
    return img

if __name__ == "__main__":
    # Get the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Set the output path
    output_path = os.path.join(script_dir, 'logo.png')
    
    # Create the logo
    create_sharpeye_logo(output_path=output_path)