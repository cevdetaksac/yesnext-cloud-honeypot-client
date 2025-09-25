#!/usr/bin/env python3#!/usr/bin/env python3#!/usr/bin/env python3

"""

Professional Icon Converter for Cloud Honeypot Client"""# -*- coding: utf-8 -*-

Converts PNG files to high-quality multi-resolution ICO files

"""Professional High-Quality Icon Converter for Cloud Honeypot Client"""



import osConverts 512px PNG files to multi-resolution ICO files with optimal qualityPNG to ICO Converter for Cloud Honeypot Client

import sys

from PIL import Image, ImageFilter, ImageEnhance"""Converts custom PNG icons to multi-resolution ICO files



def enhance_image_quality(image):"""

    """Apply quality enhancements to image"""

    try:import os

        if image.mode != 'RGBA':

            image = image.convert('RGBA')import sysfrom PIL import Image

        

        # Enhance sharpnessfrom PIL import Image, ImageFilter, ImageEnhanceimport os

        enhancer = ImageEnhance.Sharpness(image)

        image = enhancer.enhance(1.2)

        

        # Enhance contrastclass ProfessionalIconConverter:def convert_png_to_ico(png_path, ico_path, sizes=[16, 32, 48, 64, 128, 256]):

        enhancer = ImageEnhance.Contrast(image)  

        image = enhancer.enhance(1.1)    """High-quality icon converter for Windows applications"""    """Convert PNG to multi-resolution ICO file"""

        

        return image        if not os.path.exists(png_path):

    except:

        return image    def __init__(self, certs_dir: str):        print(f"❌ PNG file not found: {png_path}")



def resize_with_quality(image, size):        self.certs_dir = certs_dir        return False

    """Resize image with optimal quality"""

    if size <= 16:            

        # Small sizes - use anti-aliasing

        resized = image.resize((size, size), Image.Resampling.LANCZOS)        # ICO resolution sizes (Windows standard)    try:

        resized = resized.filter(ImageFilter.GaussianBlur(radius=0.1))

    else:        self.ico_sizes = [16, 20, 24, 28, 32, 40, 48, 64, 96, 128, 256]        # Open source PNG

        # Larger sizes - use LANCZOS

        resized = image.resize((size, size), Image.Resampling.LANCZOS)                source_img = Image.open(png_path)

    

    return resized        # Icon mappings from PNG to ICO        print(f"📁 Source: {png_path} ({source_img.size[0]}x{source_img.size[1]})")



def create_ico_from_png(png_path, ico_path, sizes=None):        self.icon_mappings = {        

    """Convert PNG to ICO with multiple resolutions"""

    try:            'default-icon.png': 'honeypot.ico',        # Convert to RGBA if needed

        if not os.path.exists(png_path):

            print(f"❌ PNG not found: {png_path}")            'green-icon.png': 'honeypot_active.ico',         if source_img.mode != 'RGBA':

            return False

                    'red-icon.png': 'honeypot_inactive.ico'            source_img = source_img.convert('RGBA')

        # Default sizes for Windows

        if sizes is None:        }        

            sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]

                        # Create different sized versions

        # Load and enhance image

        with Image.open(png_path) as source:        # System tray specific icons        images = []

            print(f"📸 Processing {os.path.basename(png_path)} ({source.width}x{source.height})")

                    self.tray_mappings = {        for size in sizes:

            enhanced = enhance_image_quality(source)

                        'default-icon.png': 'honeypot',            # Resize with high quality resampling

            # Create all resolutions

            ico_images = []            'green-icon.png': 'honeypot_active',              resized = source_img.resize((size, size), Image.Resampling.LANCZOS)

            for size in sizes:

                resized = resize_with_quality(enhanced, size)            'red-icon.png': 'honeypot_inactive'            images.append(resized)

                ico_images.append(resized)

                    }            print(f"  ✅ {size}x{size}")

            # Save as ICO

            ico_images[0].save(            

                ico_path,

                format='ICO',     def enhance_image(self, image: Image.Image) -> Image.Image:        # Save as ICO with all sizes

                sizes=[(img.width, img.height) for img in ico_images],

                append_images=ico_images[1:]        """Apply quality enhancements to image"""        images[0].save(

            )

                    try:            ico_path, 

            if os.path.exists(ico_path):

                file_size = os.path.getsize(ico_path)            # Ensure RGBA mode            format='ICO', 

                print(f"   ✅ Created {os.path.basename(ico_path)} ({file_size:,} bytes)")

                return True            if image.mode != 'RGBA':            sizes=[(s, s) for s in sizes],

                

    except Exception as e:                image = image.convert('RGBA')            append_images=images[1:]

        print(f"❌ Error converting {png_path}: {e}")

                        )

    return False

            # Enhance sharpness for better clarity        

def main():

    """Convert all PNG icons to ICO format"""            enhancer = ImageEnhance.Sharpness(image)        print(f"💾 Saved: {ico_path}")

    

    print("🎨 Cloud Honeypot Client - Professional Icon Converter")            image = enhancer.enhance(1.2)        return True

    print("=" * 60)

                        

    # Get directories

    script_dir = os.path.dirname(os.path.abspath(__file__))            # Enhance contrast slightly    except Exception as e:

    project_dir = os.path.dirname(script_dir)

    certs_dir = os.path.join(project_dir, 'certs')            enhancer = ImageEnhance.Contrast(image)        print(f"❌ Error converting {png_path}: {e}")

    

    # Check Pillow            image = enhancer.enhance(1.1)        return False

    try:

        from PIL import Image            

        print("✅ Pillow available")

    except ImportError:            return imagedef main():

        print("❌ Pillow required: pip install Pillow")

        return False                print("🔄 Converting PNG icons to ICO format...")

    

    # Icon conversion mappings        except Exception as e:    print("=" * 50)

    conversions = {

        'default-icon.png': [            print(f"⚠️ Enhancement failed: {e}")    

            ('honeypot.ico', None),  # All sizes

            ('honeypot_16.ico', [16]),            return image    # Ensure certs directory exists

            ('honeypot_32.ico', [32])

        ],        certs_dir = 'certs'

        'green-icon.png': [

            ('honeypot_active.ico', None),    def resize_optimal(self, image: Image.Image, size: int) -> Image.Image:    if not os.path.exists(certs_dir):

            ('honeypot_active_16.ico', [16]), 

            ('honeypot_active_32.ico', [32])        """Resize with optimal quality for specific size"""        print(f"❌ Certs directory not found: {certs_dir}")

        ],

        'red-icon.png': [                return

            ('honeypot_inactive.ico', None),

            ('honeypot_inactive_16.ico', [16]),        if size <= 16:    

            ('honeypot_inactive_32.ico', [32])

        ]            # Small sizes: use LANCZOS with anti-aliasing    # Icon conversion mapping

    }

                resized = image.resize((size, size), Image.Resampling.LANCZOS)    conversions = [

    # Check source files

    print("\n📋 Source PNG files:")            # Apply minimal blur to reduce pixelation        {

    for png_name in conversions.keys():

        png_path = os.path.join(certs_dir, png_name)            resized = resized.filter(ImageFilter.GaussianBlur(radius=0.1))            'png': 'certs/cloud-security.png',

        if os.path.exists(png_path):

            with Image.open(png_path) as img:        else:            'ico': 'certs/honeypot.ico',

                size = os.path.getsize(png_path)

                print(f"   📄 {png_name}: {img.width}x{img.height}, {size:,} bytes")            # Larger sizes: use LANCZOS (best quality)            'description': 'Main application icon (standard)'

        else:

            print(f"   ❌ Missing: {png_name}")            resized = image.resize((size, size), Image.Resampling.LANCZOS)        },

            return False

                    {

    print("\n🔧 Converting to ICO format...")

            return resized            'png': 'certs/cloud_green.png',

    # Convert all icons

    total_created = 0                'ico': 'certs/honeypot_active_16.ico',

    total_expected = 0

        def create_multi_resolution_ico(self, png_path: str, ico_path: str, sizes: list = None) -> bool:            'description': 'Tray icon - Active protection (16x16)',

    for png_name, ico_list in conversions.items():

        png_path = os.path.join(certs_dir, png_name)        """Create ICO with multiple resolutions from PNG"""            'sizes': [16]

        

        for ico_name, sizes in ico_list:        try:        },

            ico_path = os.path.join(certs_dir, ico_name)

                        if not os.path.exists(png_path):        {

            if create_ico_from_png(png_path, ico_path, sizes):

                total_created += 1                print(f"❌ PNG not found: {png_path}")            'png': 'certs/cloud_green.png',

            total_expected += 1

                    return False            'ico': 'certs/honeypot_active_32.ico',

    print(f"\n📊 Conversion Summary: {total_created}/{total_expected} icons created")

                            'description': 'Tray icon - Active protection (32x32)',

    if total_created == total_expected:

        print("🚀 All icons converted successfully!")            # Load source image            'sizes': [32]

        

        # List created ICO files            with Image.open(png_path) as source:        },

        print("\n📋 Created ICO files:")

        ico_files = sorted([f for f in os.listdir(certs_dir) if f.endswith('.ico')])                print(f"📸 Processing: {os.path.basename(png_path)} ({source.width}x{source.height})")        {

        for ico_file in ico_files:

            ico_path = os.path.join(certs_dir, ico_file)                            'png': 'certs/cloud_red.png',

            size = os.path.getsize(ico_path)

            print(f"   • {ico_file} ({size:,} bytes)")                # Apply enhancements            'ico': 'certs/honeypot_inactive_16.ico',

        

        return True                enhanced = self.enhance_image(source)            'description': 'Tray icon - Inactive protection (16x16)',

    else:

        print("❌ Some conversions failed")                            'sizes': [16]

        return False

                # Create resolutions        },

if __name__ == "__main__":

    success = main()                target_sizes = sizes or self.ico_sizes        {

    print()

    if success:                ico_images = []            'png': 'certs/cloud_red.png',

        print("🎉 Professional icon conversion completed!")

        print("📦 Ready for application build")                            'ico': 'certs/honeypot_inactive_32.ico',

    else:

        print("❌ Icon conversion failed")                for size in target_sizes:            'description': 'Tray icon - Inactive protection (32x32)',

    

    sys.exit(0 if success else 1)                    resized = self.resize_optimal(enhanced, size)            'sizes': [32]

                    ico_images.append(resized)        }

                    ]

                # Save as ICO with all resolutions    

                ico_images[0].save(    success_count = 0

                    ico_path,    

                    format='ICO',    for conversion in conversions:

                    sizes=[(img.width, img.height) for img in ico_images],        print(f"\n🎯 {conversion['description']}")

                    append_images=ico_images[1:]        sizes = conversion.get('sizes', [16, 32, 48, 64, 128, 256])

                )        

                        if convert_png_to_ico(conversion['png'], conversion['ico'], sizes):

                # Verify and report            success_count += 1

                if os.path.exists(ico_path):    

                    file_size = os.path.getsize(ico_path)    print("\n" + "=" * 50)

                    print(f"   ✅ {os.path.basename(ico_path)} ({file_size:,} bytes)")    print(f"✅ Conversion complete! {success_count}/{len(conversions)} successful")

                    return True    

                        # Create warning icon from red (for completeness)

        except Exception as e:    print(f"\n🎯 Creating warning tray icon...")

            print(f"❌ Failed {png_path}: {e}")    if convert_png_to_ico('certs/cloud_red.png', 'certs/honeypot_warning_16.ico', [16]):

                    print("  ✅ honeypot_warning_16.ico created")

        return False    if convert_png_to_ico('certs/cloud_red.png', 'certs/honeypot_warning_32.ico', [32]):

            print("  ✅ honeypot_warning_32.ico created")

    def create_tray_icons(self, png_path: str, base_name: str) -> int:    

        """Create system tray icons (16x16 and 32x32)"""    print("\n🎨 All icons now use your custom PNG designs!")

        success_count = 0    print("📁 Icon files updated:")

            print("   - honeypot.ico (from cloud-security.png)")

        for size in [16, 32]:    print("   - honeypot_active_*.ico (from cloud_green.png)")  

            ico_name = f"{base_name}_{size}.ico"    print("   - honeypot_inactive_*.ico (from cloud_red.png)")

            ico_path = os.path.join(self.certs_dir, ico_name)    print("   - honeypot_warning_*.ico (from cloud_red.png)")

            

            if self.create_multi_resolution_ico(png_path, ico_path, [size]):if __name__ == '__main__':

                success_count += 1    main()

        
        return success_count
    
    def process_all(self) -> bool:
        """Process all PNG files to ICO format"""
        print("🎨 Professional Icon Conversion Started")
        print("=" * 50)
        
        total_created = 0
        total_expected = 0
        
        # Check source files
        for png_name in self.icon_mappings.keys():
            png_path = os.path.join(self.certs_dir, png_name)
            if os.path.exists(png_path):
                with Image.open(png_path) as img:
                    size = os.path.getsize(png_path)
                    print(f"📄 {png_name}: {img.width}x{img.height}, {size:,} bytes")
        
        print()
        
        # Create main application icons
        print("🔧 Creating application icons...")
        for png_name, ico_name in self.icon_mappings.items():
            png_path = os.path.join(self.certs_dir, png_name)
            ico_path = os.path.join(self.certs_dir, ico_name)
            
            if self.create_multi_resolution_ico(png_path, ico_path):
                total_created += 1
            total_expected += 1
        
        print()
        
        # Create system tray icons  
        print("🖥️ Creating system tray icons...")
        for png_name, base_name in self.tray_mappings.items():
            png_path = os.path.join(self.certs_dir, png_name)
            created_count = self.create_tray_icons(png_path, base_name)
            total_created += created_count
            total_expected += 2
        
        print()
        print(f"📊 Conversion Summary: {total_created}/{total_expected} icons created")
        
        if total_created == total_expected:
            print("🚀 All icons converted successfully!")
            
            # List all ICO files
            print("\n📋 Created ICO Files:")
            ico_files = sorted([f for f in os.listdir(self.certs_dir) if f.endswith('.ico')])
            for ico_file in ico_files:
                ico_path = os.path.join(self.certs_dir, ico_file)
                size = os.path.getsize(ico_path)
                print(f"   • {ico_file} ({size:,} bytes)")
            
            return True
        else:
            print(f"⚠️ {total_expected - total_created} conversions failed")
            return False

def main():
    """Main execution"""
    
    # Get paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    certs_dir = os.path.join(project_dir, 'certs')
    
    print("🎯 Cloud Honeypot Client - Icon Converter v2.2.4")
    print("=" * 60)
    
    # Check Pillow
    try:
        from PIL import Image
        print("✅ Pillow (PIL) available")
    except ImportError:
        print("❌ Pillow required: pip install Pillow")
        return False
    
    # Check PNG sources
    required_files = ['default-icon.png', 'green-icon.png', 'red-icon.png']
    missing = [f for f in required_files if not os.path.exists(os.path.join(certs_dir, f))]
    
    if missing:
        print(f"❌ Missing PNG files: {', '.join(missing)}")
        return False
    
    print(f"📁 Working directory: {certs_dir}")
    print()
    
    # Convert icons
    converter = ProfessionalIconConverter(certs_dir)
    success = converter.process_all()
    
    print()
    if success:
        print("🎉 Professional icon conversion completed!")
        print("📦 Ready for application build")
    else:
        print("❌ Icon conversion failed")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)