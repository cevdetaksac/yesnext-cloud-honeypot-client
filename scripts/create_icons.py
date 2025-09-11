from PIL import Image, ImageDraw
import os

# Ensure certs directory exists
os.makedirs('certs', exist_ok=True)

def create_material_cloud_icon(size, bg_color, cloud_color, state='active'):
    """Create Material Design cloud icon with high quality"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Calculate scaling factor for different sizes
    scale = size / 24.0  # Material icons are typically 24x24
    
    # Background circle with slight padding
    padding = max(1, int(size * 0.1))
    bg_radius = (size - padding * 2) // 2
    center = size // 2
    
    # Draw background circle
    draw.ellipse([padding, padding, size - padding, size - padding], 
                 fill=bg_color)
    
    # Material Design Cloud path (simplified for PIL)
    # Original: M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z
    
    # Create cloud shape using circles and rounded rectangles
    cloud_size = int(size * 0.6)
    cloud_offset = (size - cloud_size) // 2
    
    # Main cloud body (large oval)
    main_w = int(cloud_size * 0.7)
    main_h = int(cloud_size * 0.45)
    main_x = cloud_offset + (cloud_size - main_w) // 2
    main_y = cloud_offset + int(cloud_size * 0.35)
    
    draw.ellipse([main_x, main_y, main_x + main_w, main_y + main_h], 
                 fill=cloud_color)
    
    # Left cloud bump
    left_r = int(cloud_size * 0.2)
    left_x = cloud_offset + int(cloud_size * 0.15)
    left_y = cloud_offset + int(cloud_size * 0.25)
    
    draw.ellipse([left_x - left_r, left_y - left_r, 
                  left_x + left_r, left_y + left_r], 
                 fill=cloud_color)
    
    # Right cloud bump  
    right_r = int(cloud_size * 0.25)
    right_x = cloud_offset + int(cloud_size * 0.75)
    right_y = cloud_offset + int(cloud_size * 0.2)
    
    draw.ellipse([right_x - right_r, right_y - right_r,
                  right_x + right_r, right_y + right_r],
                 fill=cloud_color)
    
    # Top small bump
    top_r = int(cloud_size * 0.15)
    top_x = cloud_offset + int(cloud_size * 0.45)
    top_y = cloud_offset + int(cloud_size * 0.15)
    
    draw.ellipse([top_x - top_r, top_y - top_r,
                  top_x + top_r, top_y + top_r],
                 fill=cloud_color)
    
    # Add status indicator for larger icons
    if size >= 32:
        indicator_size = max(4, int(size * 0.15))
        indicator_x = center + int(bg_radius * 0.5)
        indicator_y = center - int(bg_radius * 0.5)
        
        # Status background
        draw.ellipse([indicator_x - indicator_size, indicator_y - indicator_size,
                      indicator_x + indicator_size, indicator_y + indicator_size],
                     fill=(255, 255, 255, 255))
        
        if state == 'active':
            # Green checkmark
            line_width = max(1, indicator_size // 4)
            # Checkmark points
            p1 = (indicator_x - indicator_size//2, indicator_y)
            p2 = (indicator_x - indicator_size//4, indicator_y + indicator_size//3)
            p3 = (indicator_x + indicator_size//2, indicator_y - indicator_size//3)
            
            draw.line([p1, p2], fill=(76, 175, 80, 255), width=line_width)
            draw.line([p2, p3], fill=(76, 175, 80, 255), width=line_width)
            
        elif state == 'inactive':
            # Red X mark
            line_width = max(1, indicator_size // 3)
            margin = indicator_size // 3
            
            draw.line([indicator_x - margin, indicator_y - margin,
                       indicator_x + margin, indicator_y + margin],
                      fill=(244, 67, 54, 255), width=line_width)
            draw.line([indicator_x + margin, indicator_y - margin,
                       indicator_x - margin, indicator_y + margin],
                      fill=(244, 67, 54, 255), width=line_width)
    
    return img

def create_installer_banner():
    """Create professional installer banner"""
    banner = Image.new('RGB', (164, 314), (245, 245, 245))
    draw = ImageDraw.Draw(banner)
    
    # Gradient background
    for y in range(314):
        # Blue gradient from light to dark
        progress = y / 314
        r = int(240 - progress * 60)  # 240 -> 180
        g = int(248 - progress * 68)  # 248 -> 180  
        b = int(255 - progress * 75)  # 255 -> 180
        draw.line([(0, y), (164, y)], fill=(r, g, b))
    
    # Add main cloud icon in center
    cloud_icon = create_material_cloud_icon(64, (33, 150, 243, 255), (255, 255, 255, 255))
    banner.paste(cloud_icon, (50, 120), cloud_icon)
    
    # Add decorative bottom bar
    draw.rectangle([0, 290, 164, 314], fill=(33, 150, 243))
    
    # Add subtle top accent
    draw.rectangle([0, 0, 164, 10], fill=(66, 165, 245))
    
    return banner

# Create main application icon (multi-resolution ICO)
sizes = [16, 32, 48, 64, 128, 256]
images = []

print("Creating main application icon...")
for size in sizes:
    # Main icon - Material Blue background with white cloud
    img = create_material_cloud_icon(size, (33, 150, 243, 255), (255, 255, 255, 255))
    images.append(img)

# Save main icon as ICO
images[0].save('certs/honeypot.ico', format='ICO', 
               sizes=[(s, s) for s in sizes], append_images=images[1:])

print("Creating tray icons...")
# Create tray icons (16x16 and 32x32 for high DPI)
tray_sizes = [16, 32]

# Active state - Material Green background with white cloud
for size in tray_sizes:
    img = create_material_cloud_icon(size, (76, 175, 80, 255), (255, 255, 255, 255), 'active')
    img.save(f'certs/honeypot_active_{size}.ico', format='ICO')

# Inactive state - Material Red background with white cloud  
for size in tray_sizes:
    img = create_material_cloud_icon(size, (244, 67, 54, 255), (255, 255, 255, 255), 'inactive')
    img.save(f'certs/honeypot_inactive_{size}.ico', format='ICO')

# Warning state - Material Orange background with white cloud
for size in tray_sizes:
    img = create_material_cloud_icon(size, (255, 152, 0, 255), (255, 255, 255, 255), 'warning')
    img.save(f'certs/honeypot_warning_{size}.ico', format='ICO')

print("Creating installer banner...")
# Create welcome banner
banner = create_installer_banner()
banner.save('certs/welcome.bmp')

print("✅ High-quality Material Design icons created successfully!")
print("📁 Files generated:")
print("   - certs/honeypot.ico (main app icon - Material Blue)")
print("   - certs/honeypot_active_16.ico (tray - Material Green)")
print("   - certs/honeypot_active_32.ico (tray - Material Green HD)")
print("   - certs/honeypot_inactive_16.ico (tray - Material Red)")
print("   - certs/honeypot_inactive_32.ico (tray - Material Red HD)")
print("   - certs/honeypot_warning_16.ico (tray - Material Orange)")
print("   - certs/honeypot_warning_32.ico (tray - Material Orange HD)")
print("   - certs/welcome.bmp (installer banner - Professional gradient)")
print("🎨 All icons follow Material Design guidelines!")
