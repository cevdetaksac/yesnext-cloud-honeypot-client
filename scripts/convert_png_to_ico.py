#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PNG to ICO Converter for Cloud Honeypot Client
Converts custom PNG icons to multi-resolution ICO files
"""

from PIL import Image
import os

def convert_png_to_ico(png_path, ico_path, sizes=[16, 32, 48, 64, 128, 256]):
    """Convert PNG to multi-resolution ICO file"""
    if not os.path.exists(png_path):
        print(f"❌ PNG file not found: {png_path}")
        return False
    
    try:
        # Open source PNG
        source_img = Image.open(png_path)
        print(f"📁 Source: {png_path} ({source_img.size[0]}x{source_img.size[1]})")
        
        # Convert to RGBA if needed
        if source_img.mode != 'RGBA':
            source_img = source_img.convert('RGBA')
        
        # Create different sized versions
        images = []
        for size in sizes:
            # Resize with high quality resampling
            resized = source_img.resize((size, size), Image.Resampling.LANCZOS)
            images.append(resized)
            print(f"  ✅ {size}x{size}")
        
        # Save as ICO with all sizes
        images[0].save(
            ico_path, 
            format='ICO', 
            sizes=[(s, s) for s in sizes],
            append_images=images[1:]
        )
        
        print(f"💾 Saved: {ico_path}")
        return True
        
    except Exception as e:
        print(f"❌ Error converting {png_path}: {e}")
        return False

def main():
    print("🔄 Converting PNG icons to ICO format...")
    print("=" * 50)
    
    # Ensure certs directory exists
    certs_dir = 'certs'
    if not os.path.exists(certs_dir):
        print(f"❌ Certs directory not found: {certs_dir}")
        return
    
    # Icon conversion mapping
    conversions = [
        {
            'png': 'certs/cloud-security.png',
            'ico': 'certs/honeypot.ico',
            'description': 'Main application icon (standard)'
        },
        {
            'png': 'certs/cloud_green.png',
            'ico': 'certs/honeypot_active_16.ico',
            'description': 'Tray icon - Active protection (16x16)',
            'sizes': [16]
        },
        {
            'png': 'certs/cloud_green.png',
            'ico': 'certs/honeypot_active_32.ico',
            'description': 'Tray icon - Active protection (32x32)',
            'sizes': [32]
        },
        {
            'png': 'certs/cloud_red.png',
            'ico': 'certs/honeypot_inactive_16.ico',
            'description': 'Tray icon - Inactive protection (16x16)',
            'sizes': [16]
        },
        {
            'png': 'certs/cloud_red.png',
            'ico': 'certs/honeypot_inactive_32.ico',
            'description': 'Tray icon - Inactive protection (32x32)',
            'sizes': [32]
        }
    ]
    
    success_count = 0
    
    for conversion in conversions:
        print(f"\n🎯 {conversion['description']}")
        sizes = conversion.get('sizes', [16, 32, 48, 64, 128, 256])
        
        if convert_png_to_ico(conversion['png'], conversion['ico'], sizes):
            success_count += 1
    
    print("\n" + "=" * 50)
    print(f"✅ Conversion complete! {success_count}/{len(conversions)} successful")
    
    # Create warning icon from red (for completeness)
    print(f"\n🎯 Creating warning tray icon...")
    if convert_png_to_ico('certs/cloud_red.png', 'certs/honeypot_warning_16.ico', [16]):
        print("  ✅ honeypot_warning_16.ico created")
    if convert_png_to_ico('certs/cloud_red.png', 'certs/honeypot_warning_32.ico', [32]):
        print("  ✅ honeypot_warning_32.ico created")
    
    print("\n🎨 All icons now use your custom PNG designs!")
    print("📁 Icon files updated:")
    print("   - honeypot.ico (from cloud-security.png)")
    print("   - honeypot_active_*.ico (from cloud_green.png)")  
    print("   - honeypot_inactive_*.ico (from cloud_red.png)")
    print("   - honeypot_warning_*.ico (from cloud_red.png)")

if __name__ == '__main__':
    main()
