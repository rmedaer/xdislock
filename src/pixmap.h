#define PIXMAP_WIDTH  18
#define PIXMAP_HEIGHT 24

/**
 * for line in $(cat bitmap | tr -d '\n' | fold -w 8 | rev);
 *     do printf "0x%02x, " $(echo "ibase=2; $line" | bc);
 * done > bitmap.compiled
 */

static char pixmap_source_bits[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static char pixmap_mask_bits[] = {
    0x80, 0x07, 0x00, 0xe0, 0x1f, 0x00, 0xf0, 0x3f,
    0x00, 0x78, 0x78, 0x00, 0x3c, 0xf0, 0x00, 0x3c,
    0xf0, 0x00, 0x1c, 0xe0, 0x00, 0x1c, 0xe0, 0x00,
    0x1c, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xfc, 0xff, 0x00, 0xfe, 0xff, 0x01, 0xff,
    0xff, 0x03, 0xff, 0xfc, 0x03, 0x7f, 0xf8, 0x03,
    0x7f, 0xf8, 0x03, 0x7f, 0xf8, 0x03, 0x7f, 0xf8,
    0x03, 0x7f, 0xf8, 0x03, 0xff, 0xfc, 0x03, 0xff,
    0xff, 0x03, 0xfe, 0xff, 0x01, 0xfc, 0xff, 0x00
};