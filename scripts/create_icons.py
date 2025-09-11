from PIL import Image

# Create a simple honeypot icon (64x64 pixels)
img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))

# Drawing a simple honeypot shape
icon_data = [
    (32, 10, 'red'),  # Top
    (20, 20, 'orange'),  # Middle left
    (44, 20, 'orange'),  # Middle right
    (15, 40, 'yellow'),  # Bottom left
    (49, 40, 'yellow'),  # Bottom right
    (32, 54, 'yellow'),  # Bottom
]

for x, y, color in icon_data:
    for dx in range(-5, 6):
        for dy in range(-5, 6):
            if dx*dx + dy*dy <= 25:  # Circle with radius 5
                img.putpixel((x+dx, y+dy), {'red': (255, 0, 0, 255),
                                          'orange': (255, 165, 0, 255),
                                          'yellow': (255, 255, 0, 255)}[color])

# Save as both ICO and BMP
img.save('certs/honeypot.ico')

# Create welcome banner (164x314 pixels)
welcome = Image.new('RGB', (164, 314), 'white')
welcome.save('certs/welcome.bmp')
