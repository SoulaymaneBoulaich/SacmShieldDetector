// Generate clean standalone PNG icons for Chrome Extension using minimal PNG binary writer
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function createShieldPNG(size) {
  const width = size;
  const height = size;
  // RGBA buffer
  const buffer = Buffer.alloc(width * height * 4);

  const cx = width / 2;
  const cy = height / 2;
  const r = size * 0.42;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (y * width + x) * 4;

      // Distance from center
      const dx = (x - cx) / (width * 0.46);
      const dy = (y - cy) / (height * 0.46);

      // Rounded shield shape logic: x^2 + (y + 0.1)^2 <= 1.0, narrower towards bottom
      const shieldY = (y / height);
      const shieldHalfWidth = Math.sin(Math.min(Math.PI, shieldY * Math.PI * 0.85 + 0.2)) * 0.44;
      const normX = Math.abs(x - cx) / width;

      const inShield = normX <= shieldHalfWidth && y >= height * 0.1 && y <= height * 0.9;

      if (inShield) {
        // Gradient from cyber cyan #06b6d4 to electric blue #3b82f6 to violet #8b5cf6
        const gradT = (x + y) / (width + height);
        const red = Math.floor(16 + gradT * 80);
        const green = Math.floor(185 - gradT * 70);
        const blue = Math.floor(212 + gradT * 35);

        // Core shield icon highlight (inner emblem checkmark/crosshair)
        const inCore = Math.abs(x - cx) < size * 0.12 && Math.abs(y - cy) < size * 0.25;

        if (inCore) {
          buffer[idx] = 255;
          buffer[idx + 1] = 255;
          buffer[idx + 2] = 255;
          buffer[idx + 3] = 240;
        } else {
          buffer[idx] = red;
          buffer[idx + 1] = green;
          buffer[idx + 2] = blue;
          buffer[idx + 3] = 255;
        }
      } else {
        // Transparent background
        buffer[idx] = 0;
        buffer[idx + 1] = 0;
        buffer[idx + 2] = 0;
        buffer[idx + 3] = 0;
      }
    }
  }

  // Construct standard uncompressed/deflated PNG
  // PNG Signature: 89 50 4E 47 0D 0A 1A 0A
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  // IHDR Chunk
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr.writeUInt8(8, 8); // 8-bit depth
  ihdr.writeUInt8(6, 9); // RGBA color type
  ihdr.writeUInt8(0, 10); // compression
  ihdr.writeUInt8(0, 11); // filter
  ihdr.writeUInt8(0, 12); // interlace

  const ihdrChunk = createChunk('IHDR', ihdr);

  // Scanlines with filter byte 0 (None)
  const scanlines = Buffer.alloc(height * (width * 4 + 1));
  for (let y = 0; y < height; y++) {
    const rowOffset = y * (width * 4 + 1);
    scanlines[rowOffset] = 0; // Filter byte
    buffer.copy(scanlines, rowOffset + 1, y * width * 4, (y + 1) * width * 4);
  }

  const compressedData = zlib.deflateSync(scanlines);
  const idatChunk = createChunk('IDAT', compressedData);
  const iendChunk = createChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function createChunk(type, data) {
  const len = data.length;
  const chunk = Buffer.alloc(len + 12);
  chunk.writeUInt32BE(len, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);

  const crc = crc32(chunk.slice(4, len + 8));
  chunk.writeUInt32BE(crc, len + 8);
  return chunk;
}

// CRC32 table & calculator
let crcTable = null;
function makeCrcTable() {
  let c;
  const table = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c;
  }
  return table;
}

function crc32(buf) {
  if (!crcTable) crcTable = makeCrcTable();
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ (-1)) >>> 0;
}

const iconsDir = path.join(__dirname, '..', 'icons');
[16, 48, 128].forEach(size => {
  const png = createShieldPNG(size);
  fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), png);
  console.log(`Generated icon${size}.png (${png.length} bytes)`);
});
