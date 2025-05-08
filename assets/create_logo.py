#!/usr/bin/env python3
"""
Simple script to create a basic logo for Innora-Sentinel
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_logo():
    # Create a 400x400 image with transparent background
    img = Image.new('RGBA', (400, 400), color=(255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw a shield shape
    shield_points = [
        (200, 50),  # Top
        (350, 120),  # Top right
        (350, 250),  # Bottom right
        (200, 350),  # Bottom
        (50, 250),   # Bottom left
        (50, 120),   # Top left
    ]
    
    # Draw shield outline
    draw.polygon(shield_points, fill=(0, 80, 120, 230), outline=(0, 40, 80, 255))
    
    # Draw inner shield
    inner_shield_points = [
        (200, 70),  # Top
        (330, 130),  # Top right
        (330, 240),  # Bottom right
        (200, 330),  # Bottom
        (70, 240),   # Bottom left
        (70, 130),   # Top left
    ]
    draw.polygon(inner_shield_points, fill=(0, 100, 150, 200))
    
    # Draw an eye in the center
    eye_center = (200, 180)
    eye_radius = 50
    draw.ellipse((eye_center[0] - eye_radius, eye_center[1] - eye_radius,
                  eye_center[0] + eye_radius, eye_center[1] + eye_radius),
                 fill=(255, 255, 255, 220), outline=(0, 40, 80, 255))
    
    # Draw pupil
    pupil_radius = 20
    draw.ellipse((eye_center[0] - pupil_radius, eye_center[1] - pupil_radius,
                  eye_center[0] + pupil_radius, eye_center[1] + pupil_radius),
                 fill=(0, 40, 80, 255))
    
    # Add text "SENTINEL"
    try:
        # Try to load a font, fall back to default if not available
        font = ImageFont.truetype("Arial Bold.ttf", 36)
    except IOError:
        try:
            font = ImageFont.truetype("DejaVuSans-Bold.ttf", 36)
        except IOError:
            font = ImageFont.load_default()
    
    # Draw text
    text = "SENTINEL"
    text_width = font.getlength(text) if hasattr(font, 'getlength') else font.getsize(text)[0]
    text_position = (200 - text_width // 2, 250)
    draw.text(text_position, text, font=font, fill=(255, 255, 255, 230))
    
    # Save as PNG
    img.save('logo.png')
    print(f"Logo saved as logo.png")

if __name__ == "__main__":
    create_logo()