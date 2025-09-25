#!/usr/bin/env python3
"""
PNG to ICO Converter for Cloud Honeypot Client
Converts high-resolution PNG files to Windows ICO format
"""

import os
import sys
from PIL import Image, ImageFilter, ImageEnhance

def enhance_image(img):
    """Apply quality enhancements for high-resolution displays"""
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Yüksek çözünürlük için optimize edilmiş enhance
    # Sharpness - daha konservatif değer
    enhancer = ImageEnhance.Sharpness(img)
    img = enhancer.enhance(1.15)
    
    # Contrast - hafif artırım
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(1.05)
    
    # Color enhancement - canlılık artırma
    enhancer = ImageEnhance.Color(img)
    img = enhancer.enhance(1.1)
    
    return img

def resize_quality(img, size):
    """Resize with optimal quality for high-resolution displays"""
    if size <= 16:
        # Küçük boyutlar için anti-aliasing
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized = resized.filter(ImageFilter.GaussianBlur(radius=0.05))
    elif size <= 48:
        # Orta boyutlar için LANCZOS
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
    else:
        # Büyük boyutlar için maksimum kalite - kaynak çözünürlüğü korunur
        if img.width >= size * 2:  # Kaynak yeterince büyükse
            # Önce yarı boyuta indir, sonra hedef boyuta - daha iyi kalite
            intermediate_size = size * 2
            intermediate = img.resize((intermediate_size, intermediate_size), Image.Resampling.LANCZOS)
            resized = intermediate.resize((size, size), Image.Resampling.LANCZOS)
        else:
            resized = img.resize((size, size), Image.Resampling.LANCZOS)
    
    return resized

def convert_png_to_ico(png_path, ico_path, sizes=None):
    """Convert PNG to ICO"""
    if not os.path.exists(png_path):
        return False
    
    if sizes is None:
        # Yüksek çözünürlük için daha büyük boyutlar
        sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256, 512]
    
    try:
        with Image.open(png_path) as source:
            enhanced = enhance_image(source)
            
            ico_images = []
            for size in sizes:
                resized = resize_quality(enhanced, size)
                ico_images.append(resized)
            
            ico_images[0].save(
                ico_path,
                format='ICO',
                sizes=[(img.width, img.height) for img in ico_images],
                append_images=ico_images[1:]
            )
            
            return os.path.exists(ico_path)
    except:
        return False

def main():
    print("🎨 High-Resolution PNG to ICO Converter")
    print("   Converting 512px PNG sources to multi-resolution ICO files")
    print("=" * 60)
    
    script_dir = os.path.dirname(__file__)
    project_dir = os.path.dirname(script_dir)
    certs_dir = os.path.join(project_dir, 'certs')
    
    # Kaynak PNG dosyalarını kontrol et
    print("📋 Source PNG Files:")
    png_sources = ['default-icon.png', 'green-icon.png', 'red-icon.png']
    for png_file in png_sources:
        png_path = os.path.join(certs_dir, png_file)
        if os.path.exists(png_path):
            with Image.open(png_path) as img:
                size = os.path.getsize(png_path)
                print(f"   ✅ {png_file}: {img.width}x{img.height}, {size:,} bytes")
        else:
            print(f"   ❌ Missing: {png_file}")
    
    print(f"\n🔧 Converting to high-quality ICO format...")
    
    # Complete icon set - All resolutions for optimal Windows compatibility
    conversions = [
        # Multi-resolution base icons (16px to 512px)
        ('default-icon.png', 'honeypot.ico'),  
        ('green-icon.png', 'honeypot_active.ico'),  
        ('red-icon.png', 'honeypot_inactive.ico'),  
        
        # Individual size variants for specific use cases
        ('default-icon.png', 'honeypot_16.ico', [16, 20, 24]),
        ('default-icon.png', 'honeypot_32.ico', [32, 40, 48]),
        ('default-icon.png', 'honeypot_64.ico', [64, 72, 96]),
        ('default-icon.png', 'honeypot_128.ico', [128, 144, 192]),
        ('default-icon.png', 'honeypot_256.ico', [256, 384, 512]),
        
        # Active state variants
        ('green-icon.png', 'honeypot_active_16.ico', [16, 20, 24]),
        ('green-icon.png', 'honeypot_active_32.ico', [32, 40, 48]),
        ('green-icon.png', 'honeypot_active_64.ico', [64, 72, 96]),
        ('green-icon.png', 'honeypot_active_128.ico', [128, 144, 192]),
        ('green-icon.png', 'honeypot_active_256.ico', [256, 384, 512]),
        
        # Inactive state variants
        ('red-icon.png', 'honeypot_inactive_16.ico', [16, 20, 24]),
        ('red-icon.png', 'honeypot_inactive_32.ico', [32, 40, 48]),
        ('red-icon.png', 'honeypot_inactive_64.ico', [64, 72, 96]),
        ('red-icon.png', 'honeypot_inactive_128.ico', [128, 144, 192]),
        ('red-icon.png', 'honeypot_inactive_256.ico', [256, 384, 512]),
        
        # Warning state (using default icon as base)
        ('default-icon.png', 'honeypot_warning_16.ico', [16, 20, 24]),
        ('default-icon.png', 'honeypot_warning_32.ico', [32, 40, 48]),
    ]
    
    success_count = 0
    for conversion in conversions:
        png_name = conversion[0]
        ico_name = conversion[1]
        sizes = conversion[2] if len(conversion) > 2 else None
        
        png_path = os.path.join(certs_dir, png_name)
        ico_path = os.path.join(certs_dir, ico_name)
        
        if convert_png_to_ico(png_path, ico_path, sizes):
            file_size = os.path.getsize(ico_path)
            size_info = f"({file_size:,} bytes)" if os.path.exists(ico_path) else ""
            print(f"   ✅ {ico_name} {size_info}")
            success_count += 1
        else:
            print(f"   ❌ {ico_name}")
    
    print(f"\n📊 Conversion Summary: {success_count}/{len(conversions)} icons created")
    
    if success_count == len(conversions):
        print("🚀 All high-resolution icons converted successfully!")
        print("\n📋 Icon Quality Features:")
        print("   • Multi-resolution support (16px to 512px)")
        print("   • Enhanced sharpness and contrast")
        print("   • Optimized for high-DPI displays")
        print("   • Windows 11 compatible")
        
        # Toplam ICO dosya sayısını göster
        ico_count = len([f for f in os.listdir(certs_dir) if f.endswith('.ico')])
        print(f"   • Total ICO files: {ico_count}")
    
    return success_count == len(conversions)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)