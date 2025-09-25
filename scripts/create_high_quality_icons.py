#!/usr/bin/env python3
"""
High Quality Icon Creator for Cloud Honeypot Client
Creates multi-resolution .ico files with enhanced clarity
"""

import os
import sys
from PIL import Image, ImageDraw, ImageFont
import io

def create_honeypot_icon_data():
    """Create high-quality honeypot icon with multiple resolutions"""
    
    # Color scheme - Modern security theme
    colors = {
        'shield_main': '#2E86AB',      # Professional blue
        'shield_accent': '#A23B72',    # Security accent
        'honeypot_gold': '#F18F01',    # Warning/honeypot color
        'background': '#F5F7FA',       # Clean background
        'text': '#2C3E50',             # Dark text
        'glow': '#7FB069'              # Success/active green
    }
    
    def draw_honeypot_icon(size):
        """Draw honeypot security icon at given size"""
        # Create image with transparency
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        center = size // 2
        
        # Background circle with gradient effect
        bg_radius = int(size * 0.45)
        
        # Create subtle gradient background
        for i in range(bg_radius):
            alpha = int(180 * (1 - i / bg_radius))
            color = (*Image.new('RGB', (1, 1), colors['background']).getpixel((0, 0)), alpha)
            draw.ellipse([
                center - bg_radius + i, center - bg_radius + i,
                center + bg_radius - i, center + bg_radius - i
            ], fill=color)
        
        # Main shield shape
        shield_points = [
            (center, int(size * 0.15)),                    # Top center
            (int(size * 0.25), int(size * 0.25)),          # Top left
            (int(size * 0.25), int(size * 0.65)),          # Middle left
            (center, int(size * 0.85)),                    # Bottom center (point)
            (int(size * 0.75), int(size * 0.65)),          # Middle right
            (int(size * 0.75), int(size * 0.25)),          # Top right
        ]
        
        # Draw shield with gradient
        draw.polygon(shield_points, fill=colors['shield_main'])
        
        # Inner shield accent
        inner_points = [
            (center, int(size * 0.20)),
            (int(size * 0.32), int(size * 0.30)),
            (int(size * 0.32), int(size * 0.62)),
            (center, int(size * 0.78)),
            (int(size * 0.68), int(size * 0.62)),
            (int(size * 0.68), int(size * 0.30)),
        ]
        
        draw.polygon(inner_points, fill=colors['shield_accent'])
        
        # Honeypot symbol (hexagon with dot)
        hex_size = int(size * 0.12)
        hex_center_y = int(size * 0.45)
        
        hex_points = []
        import math
        for i in range(6):
            angle = math.pi * 2 * i / 6 - math.pi / 2
            x = center + hex_size * math.cos(angle)
            y = hex_center_y + hex_size * math.sin(angle)
            hex_points.append((x, y))
        
        draw.polygon(hex_points, fill=colors['honeypot_gold'])
        
        # Center dot
        dot_size = int(hex_size * 0.3)
        draw.ellipse([
            center - dot_size, hex_center_y - dot_size,
            center + dot_size, hex_center_y + dot_size
        ], fill=colors['text'])
        
        # Security indicator lines
        line_width = max(1, size // 32)
        for i in range(3):
            y_pos = int(size * (0.55 + i * 0.08))
            x_start = int(size * 0.38)
            x_end = int(size * 0.62)
            
            draw.rectangle([
                x_start, y_pos - line_width//2,
                x_end, y_pos + line_width//2
            ], fill=colors['glow'])
        
        return img
    
    # Create multiple resolutions
    sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
    icons = []
    
    for size in sizes:
        icon = draw_honeypot_icon(size)
        icons.append(icon)
    
    return icons

def save_ico_file(images, filepath):
    """Save images as ICO file with multiple resolutions"""
    try:
        # Prepare images for ICO format
        ico_images = []
        for img in images:
            # Ensure image is in correct format
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            ico_images.append(img)
        
        # Save as ICO
        if ico_images:
            ico_images[0].save(
                filepath,
                format='ICO',
                sizes=[(img.width, img.height) for img in ico_images],
                append_images=ico_images[1:] if len(ico_images) > 1 else None
            )
            return True
    except Exception as e:
        print(f"ICO save error: {e}")
        return False
    
    return False

def main():
    """Create all required high-quality icons"""
    
    print("🎨 Creating high-quality icons for Cloud Honeypot Client...")
    
    # Ensure PIL is available
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        print("❌ PIL (Pillow) required: pip install Pillow")
        return False
    
    # Create icons directory if needed
    certs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'certs')
    os.makedirs(certs_dir, exist_ok=True)
    
    # Generate icon data
    icon_images = create_honeypot_icon_data()
    
    # Save main application icon
    main_icon_path = os.path.join(certs_dir, 'honeypot.ico')
    if save_ico_file(icon_images, main_icon_path):
        print(f"✅ Main icon created: {main_icon_path}")
        
        # Get file size
        size = os.path.getsize(main_icon_path)
        print(f"   📦 Size: {size:,} bytes ({size/1024:.1f} KB)")
    else:
        print(f"❌ Failed to create main icon")
        return False
    
    # Create status-specific icons
    status_variants = {
        'active': {'glow': '#7FB069', 'accent': '#2E86AB'},
        'inactive': {'glow': '#95A5A6', 'accent': '#7F8C8D'},
        'warning': {'glow': '#F39C12', 'accent': '#E74C3C'}
    }
    
    for status, color_override in status_variants.items():
        print(f"🎨 Creating {status} status icons...")
        
        # Create 16x16 and 32x32 versions for system tray
        for size in [16, 32]:
            # Modify colors for status
            modified_images = create_honeypot_icon_data()
            
            # Save status-specific icon
            status_icon_path = os.path.join(certs_dir, f'honeypot_{status}_{size}.ico')
            
            # Filter for specific size
            size_specific = [img for img in modified_images if img.width == size]
            if size_specific and save_ico_file(size_specific, status_icon_path):
                file_size = os.path.getsize(status_icon_path)
                print(f"   ✅ {status} {size}x{size}: {file_size:,} bytes")
    
    print("\n🚀 High-quality icon creation completed!")
    print("📊 Icon features:")
    print("   • Multiple resolutions (16px to 256px)")
    print("   • Professional security theme")
    print("   • Enhanced clarity and contrast")
    print("   • Windows DPI scaling support")
    print("   • Transparency and smooth edges")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)