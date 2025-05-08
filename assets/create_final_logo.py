#!/usr/bin/env python3
"""
Create a refined logo for SharpEye in the style of innora.ai
"""

import os
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import numpy as np

def create_sharpeye_logo(size=(500, 500), output_path='logo.png'):
    """
    Create a modern, minimalist logo for SharpEye with a color scheme
    matching innora.ai's style, with improved design elements
    
    Args:
        size: Tuple of (width, height) for the logo
        output_path: Path to save the logo
    """
    # Create a transparent background
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Colors from innora.ai
    primary_blue = (51, 102, 255)     # #3366ff
    primary_blue_light = (92, 131, 255)  # Lighter version
    accent_green = (0, 200, 83)       # #00c853
    accent_teal = (0, 176, 155)       # Teal variation
    dark_navy = (26, 26, 46)          # #1a1a2e
    
    # Calculate center and dimensions
    width, height = size
    center_x, center_y = width // 2, height // 2
    
    # Create a circle background
    radius = min(width, height) // 2 - 20
    
    # Draw a filled circle with subtle gradient effect
    for r in range(radius, 0, -1):
        # Calculate color based on radius (slight gradient)
        factor = r / radius
        color = (
            int(dark_navy[0] * (1 - 0.2 * (1-factor))),
            int(dark_navy[1] * (1 - 0.2 * (1-factor))),
            int(dark_navy[2] * (1 - 0.2 * (1-factor)))
        )
        draw.ellipse(
            (center_x - r, center_y - r, center_x + r, center_y + r),
            outline=color, width=1
        )
    
    # Fill the main circle
    draw.ellipse(
        (center_x - radius, center_y - radius, 
         center_x + radius, center_y + radius),
        fill=dark_navy
    )
    
    # Eye shape dimensions (stylized)
    eye_width = radius * 1.5
    eye_height = radius * 0.6
    
    # Create a glossy eye outline
    outline_width = 6
    
    # Draw the eye outline with a gradient effect
    for i in range(outline_width):
        # Create a gradient from primary blue to accent teal
        blend = i / outline_width
        outline_color = (
            int(primary_blue[0] * (1-blend) + accent_teal[0] * blend),
            int(primary_blue[1] * (1-blend) + accent_teal[1] * blend),
            int(primary_blue[2] * (1-blend) + accent_teal[2] * blend)
        )
        
        # Slightly reduce size for inner rings to create gradient effect
        factor = 1 - (i * 0.15 / outline_width)
        
        draw.ellipse(
            (center_x - eye_width//2 * factor, center_y - eye_height//2 * factor,
             center_x + eye_width//2 * factor, center_y + eye_height//2 * factor),
            outline=outline_color, width=1
        )
    
    # Draw iris with gradient
    iris_radius = int(eye_height // 2)
    for r in range(iris_radius, 0, -1):
        # Calculate color based on radius (create a gradient effect)
        factor = r / iris_radius
        color = (
            int(primary_blue[0] * factor + primary_blue_light[0] * (1-factor)),
            int(primary_blue[1] * factor + primary_blue_light[1] * (1-factor)),
            int(primary_blue[2] * factor + primary_blue_light[2] * (1-factor))
        )
        draw.ellipse(
            (center_x - r, center_y - r, center_x + r, center_y + r),
            outline=color, width=1
        )
    
    # Fill the iris
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
    
    # Add a highlight (to create a glossy effect)
    highlight_radius = pupil_radius // 2
    highlight_offset_x = highlight_radius // 2
    highlight_offset_y = highlight_radius // 2
    draw.ellipse(
        (center_x - highlight_radius + highlight_offset_x, 
         center_y - highlight_radius + highlight_offset_y,
         center_x + highlight_radius + highlight_offset_x, 
         center_y + highlight_radius + highlight_offset_y),
        fill=(255, 255, 255, 200)
    )
    
    # Add a visual element to represent "sharp" vision
    num_lines = 12
    min_line_length = radius * 0.1
    max_line_length = radius * 0.3
    
    for i in range(num_lines):
        angle = 2 * np.pi * i / num_lines
        
        # Calculate line length based on position (longer at cardinal directions)
        angular_factor = abs(np.sin(angle * 2)) * 0.5 + 0.5
        line_length = min_line_length + (max_line_length - min_line_length) * angular_factor
        
        # Calculate endpoints
        r1 = radius + 2  # Start slightly outside the circle
        r2 = r1 + line_length
        
        x1 = center_x + int(r1 * np.cos(angle))
        y1 = center_y + int(r1 * np.sin(angle))
        x2 = center_x + int(r2 * np.cos(angle))
        y2 = center_y + int(r2 * np.sin(angle))
        
        # Create a gradient color for the line based on position
        t = i / num_lines
        if t < 0.5:  # Blend from blue to teal
            blend_factor = t / 0.5
            line_color = (
                int(primary_blue[0] * (1-blend_factor) + accent_teal[0] * blend_factor),
                int(primary_blue[1] * (1-blend_factor) + accent_teal[1] * blend_factor),
                int(primary_blue[2] * (1-blend_factor) + accent_teal[2] * blend_factor)
            )
        else:  # Blend from teal to blue
            blend_factor = (t - 0.5) / 0.5
            line_color = (
                int(accent_teal[0] * (1-blend_factor) + primary_blue[0] * blend_factor),
                int(accent_teal[1] * (1-blend_factor) + primary_blue[1] * blend_factor),
                int(accent_teal[2] * (1-blend_factor) + primary_blue[2] * blend_factor)
            )
        
        # Line width varies subtly with position
        line_width = int(3 + angular_factor * 2)
        
        draw.line((x1, y1, x2, y2), fill=line_color, width=line_width)
    
    # Apply a subtle blur to soften edges
    img = img.filter(ImageFilter.GaussianBlur(0.5))
    
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