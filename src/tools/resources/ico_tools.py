# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import logging
import math
import os
import struct
import subprocess
import sys
import tempfile

OPTIMIZE_PNG_FILES = 'tools/resources/optimize-png-files.sh'

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class InvalidFile(Exception):
  """Represents an invalid ICO file."""

def IsPng(png_data):
  """Determines whether a sequence of bytes is a PNG."""
  return png_data.startswith('\x89PNG\r\n\x1a\n')

def OptimizePngFile(temp_dir, png_filename, optimization_level=None):
  """Optimize a PNG file.

  Args:
    temp_dir: The directory containing the PNG file. Must be the only file in
      the directory.
    png_filename: The full path to the PNG file to optimize.

  Returns:
    The raw bytes of a PNG file, an optimized version of the input.
  """
  logging.debug('Crushing PNG image...')
  args = [OPTIMIZE_PNG_FILES]
  if optimization_level is not None:
    args.append('-o%d' % optimization_level)
  args.append(temp_dir)
  result = subprocess.call(args, stdout=sys.stderr)
  if result != 0:
    logging.warning('Warning: optimize-png-files failed (%d)', result)
  else:
    logging.debug('optimize-png-files succeeded')

  with open(png_filename, 'rb') as png_file:
    return png_file.read()

def OptimizePng(png_data, optimization_level=None):
  """Optimize a PNG.

  Args:
    png_data: The raw bytes of a PNG file.

  Returns:
    The raw bytes of a PNG file, an optimized version of the input.
  """
  temp_dir = tempfile.mkdtemp()
  try:
    logging.debug('temp_dir = %s', temp_dir)
    png_filename = os.path.join(temp_dir, 'image.png')
    with open(png_filename, 'wb') as png_file:
      png_file.write(png_data)
    return OptimizePngFile(temp_dir, png_filename,
                           optimization_level=optimization_level)

  finally:
    if os.path.exists(png_filename):
      os.unlink(png_filename)
    os.rmdir(temp_dir)

def ComputeANDMaskFromAlpha(image_data, width, height):
  """Compute an AND mask from 32-bit BGRA image data."""
  and_bytes = []
  for y in range(height):
    bit_count = 0
    current_byte = 0
    for x in range(width):
      alpha = image_data[(y * width + x) * 4 + 3]
      current_byte <<= 1
      if ord(alpha) == 0:
        current_byte |= 1
      bit_count += 1
      if bit_count == 8:
        and_bytes.append(current_byte)
        bit_count = 0
        current_byte = 0

    # At the end of a row, pad the current byte.
    if bit_count > 0:
      current_byte <<= (8 - bit_count)
      and_bytes.append(current_byte)
    # And keep padding until a multiple of 4 bytes.
    while len(and_bytes) % 4 != 0:
      and_bytes.append(0)

  and_bytes = ''.join(map(chr, and_bytes))
  return and_bytes

def RebuildANDMask(iconimage):
  """Rebuild the AND mask in an icon image.

  GIMP (<=2.8.14) creates a bad AND mask on 32-bit icon images (pixels with <50%
  opacity are marked as transparent, which end up looking black on Windows). So,
  if this is a 32-bit image, throw the mask away and recompute it from the alpha
  data. (See: https://bugzilla.gnome.org/show_bug.cgi?id=755200)

  Args:
    iconimage: Bytes of an icon image (the BMP data for an entry in an ICO
      file). Must be in BMP format, not PNG. Does not need to be 32-bit (if it
      is not 32-bit, this is a no-op).

  Returns:
    An updated |iconimage|, with the AND mask re-computed using
    ComputeANDMaskFromAlpha.
  """
  # Parse BITMAPINFOHEADER.
  (_, width, height, _, bpp, _, _, _, _, num_colors, _) = struct.unpack(
      '<LLLHHLLLLLL', iconimage[:40])

  if bpp != 32:
    # No alpha channel, so the mask cannot be "wrong" (it is the only source of
    # transparency information).
    return iconimage

  height /= 2
  xor_size = int(math.ceil(width * bpp / 32.0)) * 4 * height

  # num_colors can be 0, implying 2^bpp colors.
  xor_palette_size = (num_colors or (1 << bpp if bpp < 24 else 0)) * 4
  xor_data = iconimage[40 + xor_palette_size :
                       40 + xor_palette_size + xor_size]

  and_data = ComputeANDMaskFromAlpha(xor_data, width, height)

  # Replace the AND mask in the original icon data.
  return iconimage[:40 + xor_palette_size + xor_size] + and_data

def OptimizeIcoFile(infile, outfile, optimization_level=None):
  """Read an ICO file, optimize its PNGs, and write the output to outfile.

  Args:
    infile: The file to read from. Must be a seekable file-like object
      containing a Microsoft ICO file.
    outfile: The file to write to.
  """
  filename = os.path.basename(infile.name)
  icondir = infile.read(6)
  zero, image_type, num_images = struct.unpack('<HHH', icondir)
  if zero != 0:
    raise InvalidFile('First word must be 0.')
  if image_type not in (1, 2):
    raise InvalidFile('Image type must be 1 or 2.')

  # Read and unpack each ICONDIRENTRY.
  icon_dir_entries = []
  for i in range(num_images):
    icondirentry = infile.read(16)
    icon_dir_entries.append(struct.unpack('<BBBBHHLL', icondirentry))

  # Read each icon's bitmap data, crush PNGs, and update icon dir entries.
  current_offset = infile.tell()
  icon_bitmap_data = []
  for i in range(num_images):
    width, height, num_colors, r1, r2, r3, size, _ = icon_dir_entries[i]
    width = width or 256
    height = height or 256
    offset = current_offset
    icon_data = infile.read(size)
    if len(icon_data) != size:
      raise EOFError()

    entry_is_png = IsPng(icon_data)
    logging.info('%s entry #%d: %dx%d, %d bytes (%s)', filename, i + 1, width,
                 height, size, 'PNG' if entry_is_png else 'BMP')

    if entry_is_png:
      icon_data = OptimizePng(icon_data, optimization_level=optimization_level)
    else:
      new_icon_data = RebuildANDMask(icon_data)
      if new_icon_data != icon_data:
        logging.info('  * Rebuilt AND mask for this image from alpha channel.')
        icon_data = new_icon_data

      if width >= 256 or height >= 256:
        # TODO(mgiuca): Automatically convert large BMP images to PNGs.
        logging.warning('Entry #%d is a large image in uncompressed BMP '
                        'format. Please manually convert to PNG format before '
                        'running this utility.', i + 1)

    new_size = len(icon_data)
    current_offset += new_size
    icon_dir_entries[i] = (width % 256, height % 256, num_colors, r1, r2, r3,
                           new_size, offset)
    icon_bitmap_data.append(icon_data)

  # Write the data back to outfile.
  outfile.write(icondir)
  for icon_dir_entry in icon_dir_entries:
    outfile.write(struct.pack('<BBBBHHLL', *icon_dir_entry))
  for icon_bitmap in icon_bitmap_data:
    outfile.write(icon_bitmap)
