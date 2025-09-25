#!/usr/bin/env python3
"""
Simple high-quality icon converter for Windows
"""

from PIL import Image, ImageDraw
import os

def create_clean_honeypot_icon():
    """Create a clean, professional honeypot security icon"""
    
    # Create a 256x256 base image for maximum quality
    size = 256
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    center = size // 2
    
    # Main shield - professional blue
    shield_color = (46, 134, 171, 255)  # #2E86AB
    accent_color = (162, 59, 114, 255)  # #A23B72  
    honeypot_color = (241, 143, 1, 255) # #F18F01
    
    # Draw shield shape
    shield_points = [
        (center, 30),      # Top
        (60, 80),          # Top left
        (60, 180),         # Mid left
        (center, 230),     # Bottom point
        (196, 180),        # Mid right
        (196, 80),         # Top right
    ]
    
    draw.polygon(shield_points, fill=shield_color)
    
    # Inner shield
    inner_points = [
        (center, 50),
        (80, 95),
        (80, 170),
        (center, 210),
        (176, 170),
        (176, 95),
    ]
    
    draw.polygon(inner_points, fill=accent_color)
    
    # Honeypot symbol - hexagonal shape
    hex_center = (center, 130)
    hex_size = 25
    
    import math
    hex_points = []
    for i in range(6):
        angle = math.pi * 2 * i / 6
        x = hex_center[0] + hex_size * math.cos(angle)
        y = hex_center[1] + hex_size * math.sin(angle)
        hex_points.append((x, y))
    
    draw.polygon(hex_points, fill=honeypot_color)
    
    # Center dot
    draw.ellipse([
        center - 8, 122, center + 8, 138
    ], fill=(255, 255, 255, 255))
    
    return img

def save_multi_resolution_ico(base_image, output_path):
    """Save image as ICO with multiple resolutions"""
    
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = []
    
    for size in sizes:
        resized = base_image.resize((size, size), Image.Resampling.LANCZOS)
        images.append(resized)
    
    # Save as ICO with all sizes
    images[0].save(
        output_path,
        format='ICO',
        sizes=[(img.width, img.height) for img in images],
        append_images=images[1:]
    )

# Create main icon
print("Creating high-quality honeypot icon...")
base_icon = create_clean_honeypot_icon()

# Save to certs directory
certs_dir = r"c:\honeypot-cloud\cloud-client\certs"
icon_path = os.path.join(certs_dir, "honeypot.ico")

save_multi_resolution_ico(base_icon, icon_path)

# Check size
size = os.path.getsize(icon_path)
print(f"✅ Created: {icon_path}")
print(f"📦 Size: {size:,} bytes ({size/1024:.1f} KB)")
print("🎯 Multi-resolution ICO with sizes: 16, 24, 32, 48, 64, 128, 256px")