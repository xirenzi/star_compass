import struct
from PIL import Image, ImageDraw

# Create 32x32 PNG data first
img = Image.new('RGBA', (32, 32), (79, 70, 229, 255))
draw = ImageDraw.Draw(img)

# Draw three horizontal lines (hexagram 1 = Qian = Heaven)
draw.line([(6, 10), (26, 10)], fill=(255, 255, 255, 255), width=3)
draw.line([(6, 16), (26, 16)], fill=(255, 255, 255, 255), width=3)
draw.line([(6, 22), (26, 22)], fill=(255, 255, 255, 255), width=3)

import io
png_buf = io.BytesIO()
img.save(png_buf, format='PNG')
png_data = png_buf.getvalue()

# ICO header
ico = bytearray()
# ICONDIR
ico += struct.pack('<HHH', 0, 1, 1)  # reserved, type=1 (icon), count=1
# ICONDIRENTRY
ico += struct.pack('<BBBBHHII',
    32,     # width
    32,     # height
    0,      # color count (0 = no palette)
    0,      # reserved (MUST be 0)
    1,      # color planes
    32,     # bits per pixel
    len(png_data),  # size of image data
    22      # offset to image data (6 + 16 = 22)
)
ico += png_data

with open(r'D:\bp\star_compass\src-tauri\icons\icon.ico', 'wb') as f:
    f.write(ico)

print('ICO created, size:', len(ico))
