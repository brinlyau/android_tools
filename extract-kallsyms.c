/*
 * extract-kallsyms - Extract kernel symbol table from boot.img or raw kernel
 *
 * Supports boot image header versions 0-4 and kernel compression (LZ4, gzip).
 * Handles both pre-6.4 and 6.4+ kallsyms layouts, relative and absolute addresses.
 *
 * Self-contained: no external dependencies beyond libc.
 *
 * Usage:
 *   extract-kallsyms -i boot.img [-o output_file]
 *   extract-kallsyms -k kernel_image [-o output_file]
 *
 * Build:
 *   gcc -O2 -Wall -o extract-kallsyms extract-kallsyms.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "bootimg.h"

#define LZ4_LEGACY_MAGIC    0x184C2102
#define LZ4_LEGACY_BLOCKMAX (8 * 1024 * 1024)

#define ARM64_IMAGE_MAGIC   0x644D5241  /* "ARMd" at offset 0x38 */

#define KSYM_MIN_SYMS       1000
#define KSYM_MAX_SYMS       1000000
#define KSYM_MAX_TOKEN_LEN  256
#define KSYM_TOKEN_COUNT    256
#define KSYM_NAME_MAXLEN    512

/* ---- Helpers ---- */

static void *load_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s': %s\n", path, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        fclose(f);
        return NULL;
    }
    void *data = malloc(sz);
    if (!data) {
        fclose(f);
        return NULL;
    }
    if (fread(data, 1, sz, f) != (size_t)sz) {
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_size = sz;
    return data;
}

static inline uint16_t get_u16(const uint8_t *p) { return p[0] | (p[1] << 8); }
static inline uint32_t get_u32(const uint8_t *p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint64_t get_u64(const uint8_t *p)
{
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p + 4) << 32);
}
static inline int32_t get_s32(const uint8_t *p) { return (int32_t)get_u32(p); }

static inline size_t align_up(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }

/* ================================================================
 * Embedded LZ4 block decompressor (BSD-2-Clause compatible)
 *
 * Handles the LZ4 block format: sequences of literal runs and
 * match copies with 2-byte little-endian back-reference offsets.
 * ================================================================ */

static int lz4_block_decode(const uint8_t *src, int src_len,
                            uint8_t *dst, int dst_cap)
{
    const uint8_t *ip = src, *ip_end = src + src_len;
    uint8_t *op = dst, *op_end = dst + dst_cap;

    for (;;) {
        if (ip >= ip_end)
            return -1;

        unsigned token = *ip++;

        /* Literal run */
        unsigned lit_len = token >> 4;
        if (lit_len == 15) {
            unsigned s;
            do {
                if (ip >= ip_end) return -1;
                s = *ip++;
                lit_len += s;
            } while (s == 255);
        }

        if ((size_t)(ip_end - ip) < lit_len || (size_t)(op_end - op) < lit_len)
            return -1;
        memcpy(op, ip, lit_len);
        ip += lit_len;
        op += lit_len;

        /* Last sequence ends after literals (no match) */
        if (ip >= ip_end)
            break;

        /* Match offset (2 bytes LE) */
        if (ip + 2 > ip_end) return -1;
        unsigned offset = ip[0] | ((unsigned)ip[1] << 8);
        ip += 2;
        if (offset == 0 || (size_t)(op - dst) < offset)
            return -1;

        /* Match length (minimum 4) */
        unsigned match_len = (token & 0xf) + 4;
        if ((token & 0xf) == 15) {
            unsigned s;
            do {
                if (ip >= ip_end) return -1;
                s = *ip++;
                match_len += s;
            } while (s == 255);
        }

        if ((size_t)(op_end - op) < match_len)
            return -1;

        /* Byte-by-byte copy handles overlapping matches */
        const uint8_t *ref = op - offset;
        for (unsigned i = 0; i < match_len; i++)
            op[i] = ref[i];
        op += match_len;
    }

    return (int)(op - dst);
}

/* ================================================================
 * Embedded DEFLATE (RFC 1951) / gzip (RFC 1952) decompressor
 *
 * Minimal implementation supporting stored, fixed, and dynamic
 * Huffman blocks. Output buffer grows dynamically via realloc.
 * ================================================================ */

/* --- Bit reader (LSB-first within each byte) --- */

struct inf_bits {
    const uint8_t *src;
    size_t len;
    size_t pos;
    uint32_t buf;
    int n;
};

static void inf_bits_init(struct inf_bits *b, const uint8_t *src, size_t len)
{
    b->src = src; b->len = len; b->pos = 0; b->buf = 0; b->n = 0;
}

static void inf_bits_fill(struct inf_bits *b)
{
    while (b->n <= 24 && b->pos < b->len) {
        b->buf |= (uint32_t)b->src[b->pos++] << b->n;
        b->n += 8;
    }
}

/* Read k bits (k <= 16) */
static uint32_t inf_bits_read(struct inf_bits *b, int k)
{
    inf_bits_fill(b);
    uint32_t v = b->buf & ((1u << k) - 1);
    b->buf >>= k;
    b->n -= k;
    return v;
}

/* Discard bits to reach byte boundary */
static void inf_bits_align(struct inf_bits *b)
{
    int discard = b->n & 7;
    b->buf >>= discard;
    b->n -= discard;
}

/* --- Huffman table --- */

#define INF_MAXBITS   15
#define INF_MAXLCODES 286
#define INF_MAXDCODES 30
#define INF_MAXCODES  (INF_MAXLCODES + INF_MAXDCODES)
#define INF_FIXLCODES 288  /* fixed table uses 288 entries */

struct inf_huff {
    short count[INF_MAXBITS + 1];
    short symbol[INF_FIXLCODES]; /* large enough for any table */
};

static int inf_huff_build(struct inf_huff *h, const short *lens, int n)
{
    short offsets[INF_MAXBITS + 1];
    int i;

    memset(h->count, 0, sizeof(h->count));
    for (i = 0; i < n; i++)
        h->count[lens[i]]++;
    h->count[0] = 0;

    offsets[0] = 0;
    offsets[1] = 0;
    for (i = 1; i < INF_MAXBITS; i++)
        offsets[i + 1] = offsets[i] + h->count[i];

    for (i = 0; i < n; i++)
        if (lens[i])
            h->symbol[offsets[lens[i]]++] = (short)i;

    return 0;
}

/*
 * Decode one Huffman symbol.
 * Uses the canonical code property: all codes of length L form a
 * contiguous range. Walk bit by bit, comparing the accumulated code
 * against each range.
 */
static int inf_huff_sym(struct inf_huff *h, struct inf_bits *b)
{
    int code = 0, first = 0, index = 0;

    for (int len = 1; len <= INF_MAXBITS; len++) {
        code |= (int)inf_bits_read(b, 1);
        int cnt = h->count[len];
        if (code - cnt < first)
            return h->symbol[index + (code - first)];
        index += cnt;
        first += cnt;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

/* --- DEFLATE tables --- */

static const short inf_len_base[29] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,
    35,43,51,59,67,83,99,115,131,163,195,227,258
};
static const short inf_len_extra[29] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,
    3,3,3,3,4,4,4,4,5,5,5,5,0
};
static const short inf_dist_base[30] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,
    257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
};
static const short inf_dist_extra[30] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,
    7,7,8,8,9,9,10,10,11,11,12,12,13,13
};
static const int inf_cl_order[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
};

/* --- Inflate engine with growable output --- */

struct inf_state {
    struct inf_bits bits;
    uint8_t *out;
    size_t len;
    size_t cap;
};

static int inf_grow(struct inf_state *s, size_t need)
{
    while (s->len + need > s->cap) {
        size_t nc = s->cap < 65536 ? 65536 : s->cap * 2;
        uint8_t *p = realloc(s->out, nc);
        if (!p) return -1;
        s->out = p;
        s->cap = nc;
    }
    return 0;
}

/* Decode a Huffman-compressed block (fixed or dynamic tables) */
static int inf_codes(struct inf_state *s, struct inf_huff *lc, struct inf_huff *dc)
{
    for (;;) {
        int sym = inf_huff_sym(lc, &s->bits);
        if (sym < 0) return -1;

        if (sym < 256) {
            if (inf_grow(s, 1)) return -1;
            s->out[s->len++] = (uint8_t)sym;
        } else if (sym == 256) {
            return 0;
        } else {
            sym -= 257;
            if (sym >= 29) return -1;

            unsigned length = inf_len_base[sym] + inf_bits_read(&s->bits, inf_len_extra[sym]);

            int dsym = inf_huff_sym(dc, &s->bits);
            if (dsym < 0 || dsym >= 30) return -1;

            unsigned dist = inf_dist_base[dsym] + inf_bits_read(&s->bits, inf_dist_extra[dsym]);

            if (dist > s->len) return -1;
            if (inf_grow(s, length)) return -1;

            for (unsigned i = 0; i < length; i++) {
                s->out[s->len] = s->out[s->len - dist];
                s->len++;
            }
        }
    }
}

/* Stored (uncompressed) block */
static int inf_stored(struct inf_state *s)
{
    inf_bits_align(&s->bits);

    unsigned lo = inf_bits_read(&s->bits, 16);
    unsigned hi = inf_bits_read(&s->bits, 16);
    if (lo != (~hi & 0xffff)) return -1;

    if (inf_grow(s, lo)) return -1;

    for (unsigned i = 0; i < lo; i++) {
        if (s->bits.pos >= s->bits.len) return -1;
        s->out[s->len++] = s->bits.src[s->bits.pos++];
    }
    s->bits.buf = 0;
    s->bits.n = 0;
    return 0;
}

/* Fixed Huffman block */
static int inf_fixed(struct inf_state *s)
{
    struct inf_huff lc, dc;
    short lens[INF_FIXLCODES];
    int i;

    for (i = 0; i < 144; i++) lens[i] = 8;
    for (; i < 256; i++)      lens[i] = 9;
    for (; i < 280; i++)      lens[i] = 7;
    for (; i < INF_FIXLCODES; i++) lens[i] = 8;
    inf_huff_build(&lc, lens, INF_FIXLCODES);

    for (i = 0; i < 30; i++) lens[i] = 5;
    inf_huff_build(&dc, lens, 30);

    return inf_codes(s, &lc, &dc);
}

/* Dynamic Huffman block */
static int inf_dynamic(struct inf_state *s)
{
    int nlit  = (int)inf_bits_read(&s->bits, 5) + 257;
    int ndist = (int)inf_bits_read(&s->bits, 5) + 1;
    int nclen = (int)inf_bits_read(&s->bits, 4) + 4;

    if (nlit > INF_MAXLCODES || ndist > INF_MAXDCODES)
        return -1;

    /* Read code-length code lengths */
    short cllens[19];
    memset(cllens, 0, sizeof(cllens));
    for (int i = 0; i < nclen; i++)
        cllens[inf_cl_order[i]] = (short)inf_bits_read(&s->bits, 3);

    struct inf_huff clhuff;
    inf_huff_build(&clhuff, cllens, 19);

    /* Decode literal/length + distance code lengths */
    int total = nlit + ndist;
    short lens[INF_MAXCODES];
    int i = 0;

    while (i < total) {
        int sym = inf_huff_sym(&clhuff, &s->bits);
        if (sym < 0) return -1;

        if (sym < 16) {
            lens[i++] = (short)sym;
        } else if (sym == 16) {
            if (i == 0) return -1;
            int rep = 3 + (int)inf_bits_read(&s->bits, 2);
            short val = lens[i - 1];
            while (rep-- && i < total) lens[i++] = val;
        } else if (sym == 17) {
            int rep = 3 + (int)inf_bits_read(&s->bits, 3);
            while (rep-- && i < total) lens[i++] = 0;
        } else { /* 18 */
            int rep = 11 + (int)inf_bits_read(&s->bits, 7);
            while (rep-- && i < total) lens[i++] = 0;
        }
    }

    struct inf_huff lc, dc;
    inf_huff_build(&lc, lens, nlit);
    inf_huff_build(&dc, lens + nlit, ndist);

    return inf_codes(s, &lc, &dc);
}

/* Inflate a raw DEFLATE stream */
static int inf_inflate(const uint8_t *src, size_t src_len,
                       uint8_t **out, size_t *out_len)
{
    struct inf_state s;
    memset(&s, 0, sizeof(s));
    inf_bits_init(&s.bits, src, src_len);

    int last, err;
    do {
        last = (int)inf_bits_read(&s.bits, 1);
        int type = (int)inf_bits_read(&s.bits, 2);

        switch (type) {
        case 0: err = inf_stored(&s);  break;
        case 1: err = inf_fixed(&s);   break;
        case 2: err = inf_dynamic(&s); break;
        default: err = -1;             break;
        }
        if (err) { free(s.out); return -1; }
    } while (!last);

    *out = s.out;
    *out_len = s.len;
    return 0;
}

/* Parse gzip header and inflate the payload */
static int gzip_decompress(const uint8_t *src, size_t src_len,
                           uint8_t **out, size_t *out_len)
{
    if (src_len < 10 || src[0] != 0x1f || src[1] != 0x8b || src[2] != 0x08)
        return -1;

    uint8_t flg = src[3];
    size_t pos = 10;

    /* FEXTRA */
    if (flg & 0x04) {
        if (pos + 2 > src_len) return -1;
        unsigned xlen = src[pos] | ((unsigned)src[pos + 1] << 8);
        pos += 2 + xlen;
    }
    /* FNAME */
    if (flg & 0x08) {
        while (pos < src_len && src[pos]) pos++;
        pos++;
    }
    /* FCOMMENT */
    if (flg & 0x10) {
        while (pos < src_len && src[pos]) pos++;
        pos++;
    }
    /* FHCRC */
    if (flg & 0x02)
        pos += 2;

    if (pos >= src_len)
        return -1;

    return inf_inflate(src + pos, src_len - pos, out, out_len);
}

/* ---- Kernel extraction from boot.img ---- */

static uint8_t *extract_kernel_from_bootimg(const uint8_t *img, size_t img_size, size_t *kern_size)
{
    if (img_size < BOOT_MAGIC_SIZE)
        return NULL;

    if (memcmp(img, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0) {
        fprintf(stderr, "error: not a boot image (no ANDROID! magic)\n");
        return NULL;
    }

    boot_img_hdr_v3 hdr3;
    memcpy(&hdr3, img, sizeof(hdr3) < img_size ? sizeof(hdr3) : img_size);

    uint32_t kernel_size;
    uint32_t pagesize;
    size_t kernel_offset;

    if (hdr3.header_version >= 3) {
        pagesize = 4096;
        kernel_size = hdr3.kernel_size;
        kernel_offset = pagesize;
    } else {
        boot_img_hdr_v2 hdr2;
        memcpy(&hdr2, img, sizeof(hdr2) < img_size ? sizeof(hdr2) : img_size);
        pagesize = hdr2.page_size;
        kernel_size = hdr2.kernel_size;
        kernel_offset = pagesize;
    }

    if (kernel_offset + kernel_size > img_size) {
        fprintf(stderr, "error: kernel extends past end of image\n");
        return NULL;
    }

    fprintf(stderr, "boot.img: header_version=%d kernel_size=%u pagesize=%u\n",
            hdr3.header_version >= 3 ? hdr3.header_version : ((boot_img_hdr_v2 *)img)->header_version,
            kernel_size, pagesize);

    uint8_t *kernel = malloc(kernel_size);
    if (!kernel)
        return NULL;
    memcpy(kernel, img + kernel_offset, kernel_size);
    *kern_size = kernel_size;
    return kernel;
}

/* ---- LZ4 legacy decompression ---- */

static uint8_t *decompress_lz4_legacy(const uint8_t *src, size_t src_size, size_t *out_size)
{
    if (src_size < 4 || get_u32(src) != LZ4_LEGACY_MAGIC)
        return NULL;

    size_t capacity = LZ4_LEGACY_BLOCKMAX * 2;
    uint8_t *out = malloc(capacity);
    if (!out)
        return NULL;

    size_t total = 0;
    size_t offset = 4;

    while (offset + 4 <= src_size) {
        uint32_t block_size = get_u32(src + offset);
        offset += 4;

        if (block_size == 0 || offset + block_size > src_size)
            break;

        while (total + LZ4_LEGACY_BLOCKMAX > capacity) {
            capacity *= 2;
            uint8_t *tmp = realloc(out, capacity);
            if (!tmp) { free(out); return NULL; }
            out = tmp;
        }

        int dec = lz4_block_decode(src + offset, (int)block_size,
                                   out + total, LZ4_LEGACY_BLOCKMAX);
        if (dec <= 0)
            break;

        total += dec;
        offset += block_size;
    }

    if (total == 0) {
        free(out);
        return NULL;
    }

    fprintf(stderr, "LZ4 decompressed: %zu -> %zu bytes\n", src_size, total);
    *out_size = total;
    return out;
}

/* ---- gzip decompression ---- */

static uint8_t *decompress_gzip_wrapper(const uint8_t *src, size_t src_size, size_t *out_size)
{
    if (src_size < 2 || src[0] != 0x1f || src[1] != 0x8b)
        return NULL;

    uint8_t *out = NULL;
    size_t out_len = 0;

    if (gzip_decompress(src, src_size, &out, &out_len) != 0)
        return NULL;

    fprintf(stderr, "gzip decompressed: %zu -> %zu bytes\n", src_size, out_len);
    *out_size = out_len;
    return out;
}

/* ---- Kernel decompression ---- */

static uint8_t *decompress_kernel(const uint8_t *kernel, size_t kern_size, size_t *out_size)
{
    uint8_t *decompressed = NULL;

    if (kern_size >= 4 && get_u32(kernel) == LZ4_LEGACY_MAGIC) {
        fprintf(stderr, "Kernel is LZ4 legacy compressed\n");
        decompressed = decompress_lz4_legacy(kernel, kern_size, out_size);
        if (decompressed)
            return decompressed;
    }

    if (kern_size >= 2 && kernel[0] == 0x1f && kernel[1] == 0x8b) {
        fprintf(stderr, "Kernel is gzip compressed\n");
        decompressed = decompress_gzip_wrapper(kernel, kern_size, out_size);
        if (decompressed)
            return decompressed;
    }

    if (kern_size > 0x40) {
        uint32_t arm64_magic = get_u32(kernel + 0x38);
        if (arm64_magic == ARM64_IMAGE_MAGIC) {
            fprintf(stderr, "Kernel is uncompressed ARM64 Image\n");
            *out_size = kern_size;
            uint8_t *copy = malloc(kern_size);
            if (copy) {
                memcpy(copy, kernel, kern_size);
                return copy;
            }
        }
    }

    /* Search inside blob for compressed payloads */
    fprintf(stderr, "Searching for compressed payload inside kernel blob...\n");
    for (size_t i = 0; i + 4 < kern_size; i++) {
        if (get_u32(kernel + i) == LZ4_LEGACY_MAGIC) {
            fprintf(stderr, "Found LZ4 legacy payload at offset 0x%zx\n", i);
            decompressed = decompress_lz4_legacy(kernel + i, kern_size - i, out_size);
            if (decompressed)
                return decompressed;
        }
        if (kernel[i] == 0x1f && kernel[i + 1] == 0x8b && kernel[i + 2] == 0x08) {
            fprintf(stderr, "Found gzip payload at offset 0x%zx\n", i);
            decompressed = decompress_gzip_wrapper(kernel + i, kern_size - i, out_size);
            if (decompressed && *out_size > kern_size / 2)
                return decompressed;
            free(decompressed);
            decompressed = NULL;
        }
    }

    fprintf(stderr, "No compression detected, using raw kernel\n");
    *out_size = kern_size;
    uint8_t *copy = malloc(kern_size);
    if (copy)
        memcpy(copy, kernel, kern_size);
    return copy;
}

/* ---- kallsyms extraction ---- */

struct kallsyms {
    const uint8_t *data;
    size_t size;

    size_t token_table_off;
    size_t token_index_off;
    size_t markers_off;
    size_t markers_count;
    size_t names_off;
    size_t num_syms_off;
    size_t num_syms;
    size_t addrs_off;

    char tokens[KSYM_TOKEN_COUNT][KSYM_MAX_TOKEN_LEN];

    bool is_relative;
    uint64_t relative_base;
    bool is_v64;        /* kernel 6.4+ layout: offsets after token_index */

    int ptr_size;       /* target pointer size (4 or 8) */
};

/*
 * Find token_table and token_index.
 *
 * token_index is an array of 256 monotonically increasing uint16_t values
 * starting with 0. token_table immediately precedes it (possibly with
 * null padding). We scan backwards for token_index candidates and
 * cross-validate by walking all 256 tokens.
 */
static bool find_token_table(struct kallsyms *ks)
{
    const uint8_t *d = ks->data;
    size_t sz = ks->size;

    size_t ti_size = KSYM_TOKEN_COUNT * 2; /* 512 bytes */

    for (size_t i = sz - ti_size; i > sz / 4; i -= 4) {
        if (i + ti_size > sz)
            continue;
        if (get_u16(d + i) != 0)
            continue;

        uint16_t v1 = get_u16(d + i + 2);
        if (v1 == 0 || v1 > 100)
            continue;
        uint16_t v255 = get_u16(d + i + 255 * 2);
        if (v255 <= v1 || v255 < 256 || v255 > 8192)
            continue;

        /* Full monotonic check */
        bool mono = true;
        uint16_t prev = 0;
        for (int j = 1; j < 256; j++) {
            uint16_t v = get_u16(d + i + j * 2);
            if (v <= prev) { mono = false; break; }
            prev = v;
        }
        if (!mono)
            continue;

        /*
         * Compute token_table start. Try multiple last-token lengths
         * to handle null padding between token_table end and token_index.
         */
        bool found = false;
        for (int last_tok_len = 0; last_tok_len <= 50; last_tok_len++) {
            size_t total_tt_size = v255 + last_tok_len + 1;
            if (total_tt_size > i)
                break;
            size_t tt_start = i - total_tt_size;

            /* Cross-validate all 256 token offsets */
            size_t pos = tt_start;
            bool valid = true;
            int avg_len_sum = 0;
            char temp_tokens[KSYM_TOKEN_COUNT][KSYM_MAX_TOKEN_LEN];

            for (int j = 0; j < 256; j++) {
                size_t expected_off = get_u16(d + i + j * 2);
                size_t actual_off = pos - tt_start;
                if (expected_off != actual_off) {
                    valid = false;
                    break;
                }
                if (pos >= i) {
                    valid = false;
                    break;
                }
                size_t tok_start = pos;
                while (pos < i && d[pos] != '\0') {
                    if (!isprint(d[pos])) { valid = false; break; }
                    pos++;
                }
                if (!valid || pos >= i + 1)
                    break;
                size_t tlen = pos - tok_start;
                avg_len_sum += tlen;
                if (tlen >= KSYM_MAX_TOKEN_LEN)
                    tlen = KSYM_MAX_TOKEN_LEN - 1;
                memcpy(temp_tokens[j], d + tok_start, tlen);
                temp_tokens[j][tlen] = '\0';
                pos++;
            }
            if (!valid)
                continue;

            double avg_len = (double)avg_len_sum / 256.0;
            if (avg_len < 1.5)
                continue;

            ks->token_table_off = tt_start;
            ks->token_index_off = i;
            memcpy(ks->tokens, temp_tokens, sizeof(temp_tokens));

            fprintf(stderr, "Found token_table at 0x%zx, token_index at 0x%zx (avg token len: %.1f)\n",
                    tt_start, i, avg_len);
            found = true;
            break;
        }
        if (found)
            return true;
    }
    return false;
}

/*
 * Find markers: array of ascending uint32_t values before token_table.
 * markers[0] is always 0.
 */
static bool find_markers(struct kallsyms *ks)
{
    const uint8_t *d = ks->data;
    size_t search_end = ks->token_table_off;
    size_t search_start = search_end > 0x400000 ? search_end - 0x400000 : 0;

    for (size_t pos = search_end - 4; pos > search_start; pos -= 4) {
        pos = pos & ~3;
        if (get_u32(d + pos) != 0)
            continue;

        size_t count = 0;
        uint32_t prev_val = 0;
        size_t p = pos;

        while (p + 4 <= search_end) {
            uint32_t val = get_u32(d + p);
            if (count > 0 && val <= prev_val)
                break;
            if (val > 0x4000000)
                break;
            prev_val = val;
            count++;
            p += 4;
        }

        size_t approx_syms = (count - 1) * 256;
        if (count < 10 || approx_syms < KSYM_MIN_SYMS || approx_syms > KSYM_MAX_SYMS)
            continue;

        ks->markers_off = pos;
        ks->markers_count = count;

        fprintf(stderr, "Found markers at 0x%zx, count=%zu (approx %zu syms)\n",
                pos, count, approx_syms);
        return true;
    }
    return false;
}

/*
 * Find num_syms and names.
 * num_syms is stored as a uint32 before the names section.
 * Walking num_syms name entries from names_start must land near markers_off.
 */
static bool find_num_syms_and_names(struct kallsyms *ks)
{
    const uint8_t *d = ks->data;
    size_t search_start = ks->markers_off > 0x400000 ? ks->markers_off - 0x400000 : 0;

    for (size_t off = ks->markers_off - 4; off > search_start; off -= 4) {
        off = off & ~3;

        uint32_t candidate = get_u32(d + off);
        if (candidate < KSYM_MIN_SYMS || candidate > KSYM_MAX_SYMS)
            continue;

        size_t expected_markers = (candidate + 255) / 256;
        /* Allow +/-2 tolerance: markers scan may overcount if next value is ascending */
        if (expected_markers > ks->markers_count + 2 || expected_markers + 2 < ks->markers_count)
            continue;

        /* Try names starting at off + 4 and off + 8 (for alignment padding) */
        for (int padding = 4; padding <= 8; padding += 4) {
            size_t names_start = off + padding;
            if (names_start >= ks->markers_off)
                continue;

            size_t pos = names_start;
            bool valid = true;

            for (size_t s = 0; s < candidate; s++) {
                if (pos >= ks->markers_off) { valid = false; break; }
                uint8_t nlen = d[pos];
                if (nlen == 0) { valid = false; break; }
                pos += 1 + nlen;
            }

            /* Allow alignment padding (up to 16 bytes) between names and markers */
            if (!valid || pos > ks->markers_off || (ks->markers_off - pos) > 16)
                continue;

            ks->num_syms = candidate;
            ks->num_syms_off = off;
            ks->names_off = names_start;

            fprintf(stderr, "Found num_syms=%zu at 0x%zx, names at 0x%zx\n",
                    ks->num_syms, off, names_start);
            return true;
        }
    }
    return false;
}

/*
 * Find addresses/offsets.
 *
 * Pre-6.4:  offsets[] -> relative_base -> num_syms -> names -> markers -> token_table -> token_index
 * 6.4+:     num_syms -> names -> markers -> token_table -> token_index -> offsets[] -> relative_base
 */
static bool find_addresses(struct kallsyms *ks)
{
    const uint8_t *d = ks->data;
    int ps = ks->ptr_size;
    size_t n = ks->num_syms;
    size_t ti_end = ks->token_index_off + KSYM_TOKEN_COUNT * 2;

    /* ---- Try 6.4+ layout: offsets after token_index ---- */
    {
        size_t offsets_start = align_up(ti_end, ps);
        size_t offsets_end_rel = offsets_start + n * 4;
        size_t rb_off = align_up(offsets_end_rel, ps);

        if (rb_off + ps <= ks->size) {
            uint64_t base = (ps == 8) ? get_u64(d + rb_off) : get_u32(d + rb_off);

            bool valid_base = false;
            if (ps == 8)
                valid_base = (base >> 32) >= 0xffffffc0;
            else
                valid_base = (base >> 24) >= 0xc0;

            if (valid_base) {
                int32_t off0 = get_s32(d + offsets_start);
                uint64_t addr0 = base + off0;

                bool valid_addr = false;
                if (ps == 8)
                    valid_addr = (addr0 >> 32) >= 0xffffffc0;
                else
                    valid_addr = (addr0 >> 24) >= 0xc0;

                if (valid_addr) {
                    ks->is_v64 = true;
                    ks->is_relative = true;
                    ks->relative_base = base;
                    ks->addrs_off = offsets_start;

                    fprintf(stderr, "Found 6.4+ layout: offsets at 0x%zx, relative_base=0x%016lx at 0x%zx\n",
                            offsets_start, (unsigned long)base, rb_off);
                    return true;
                }
            }

            /* Also try absolute addresses after token_index */
            size_t addrs_start = align_up(ti_end, ps);
            size_t addrs_end = addrs_start + n * ps;

            if (addrs_end + ps <= ks->size) {
                uint64_t a0 = (ps == 8) ? get_u64(d + addrs_start) : get_u32(d + addrs_start);
                bool va = (ps == 8) ? ((a0 >> 32) >= 0xffffffc0) : ((a0 >> 24) >= 0xc0);
                if (va) {
                    ks->is_v64 = true;
                    ks->is_relative = false;
                    ks->addrs_off = addrs_start;

                    fprintf(stderr, "Found 6.4+ layout: absolute addresses at 0x%zx\n", addrs_start);
                    return true;
                }
            }
        }
    }

    /* ---- Try pre-6.4 layout: offsets/addresses before num_syms ---- */

    /* Relative: offsets[n] (4 bytes each) + relative_base (ps) + num_syms */
    {
        size_t rb_off = ks->num_syms_off - ps;
        size_t offsets_size = n * 4;

        if (rb_off >= offsets_size) {
            size_t offsets_off = rb_off - offsets_size;
            uint64_t base = (ps == 8) ? get_u64(d + rb_off) : get_u32(d + rb_off);

            bool valid_base = (ps == 8) ? ((base >> 32) >= 0xffffffc0) : ((base >> 24) >= 0xc0);
            if (valid_base) {
                int32_t off0 = get_s32(d + offsets_off);
                uint64_t addr0 = base + off0;
                bool valid_addr = (ps == 8) ? ((addr0 >> 32) >= 0xffffffc0) : ((addr0 >> 24) >= 0xc0);

                if (valid_addr) {
                    ks->is_v64 = false;
                    ks->is_relative = true;
                    ks->relative_base = base;
                    ks->addrs_off = offsets_off;

                    fprintf(stderr, "Found pre-6.4 layout: offsets at 0x%zx, relative_base=0x%016lx\n",
                            offsets_off, (unsigned long)base);
                    return true;
                }
            }
        }
    }

    /* Absolute: addresses[n] (ps each) + num_syms */
    {
        size_t addrs_size = n * ps;
        if (ks->num_syms_off >= addrs_size) {
            size_t addrs_off = ks->num_syms_off - addrs_size;
            uint64_t a0 = (ps == 8) ? get_u64(d + addrs_off) : get_u32(d + addrs_off);

            bool va = (ps == 8) ? ((a0 >> 32) >= 0xffffffc0) : ((a0 >> 24) >= 0xc0);
            if (va) {
                ks->is_v64 = false;
                ks->is_relative = false;
                ks->addrs_off = addrs_off;

                fprintf(stderr, "Found pre-6.4 layout: absolute addresses at 0x%zx\n", addrs_off);
                return true;
            }
        }
    }

    fprintf(stderr, "warning: could not locate address table, printing names only\n");
    ks->addrs_off = 0;
    return true;
}

/*
 * Decode a compressed kallsyms name using the token table.
 */
static int decode_name(struct kallsyms *ks, const uint8_t *src, uint8_t nlen,
                       char *out, size_t out_max)
{
    size_t pos = 0;
    for (int i = 0; i < nlen && pos < out_max - 1; i++) {
        uint8_t token = src[i];
        const char *expansion = ks->tokens[token];
        size_t elen = strlen(expansion);
        if (pos + elen >= out_max)
            break;
        memcpy(out + pos, expansion, elen);
        pos += elen;
    }
    out[pos] = '\0';
    return pos;
}

/*
 * Get symbol address for symbol index i.
 */
static uint64_t get_sym_addr(struct kallsyms *ks, size_t i)
{
    const uint8_t *d = ks->data;

    if (ks->addrs_off == 0)
        return 0;

    if (ks->is_relative) {
        int32_t offset = get_s32(d + ks->addrs_off + i * 4);
        if (offset >= 0)
            return ks->relative_base + offset;
        return ks->relative_base - 1 - (uint64_t)(uint32_t)(~offset);
    } else {
        if (ks->ptr_size == 8)
            return get_u64(d + ks->addrs_off + i * ks->ptr_size);
        else
            return get_u32(d + ks->addrs_off + i * ks->ptr_size);
    }
}

/*
 * Print all symbols.
 */
static void print_kallsyms(struct kallsyms *ks, FILE *out)
{
    const uint8_t *d = ks->data;
    size_t pos = ks->names_off;
    char name[KSYM_NAME_MAXLEN];
    size_t count = 0;

    for (size_t i = 0; i < ks->num_syms; i++) {
        uint8_t nlen = d[pos];
        pos++;

        decode_name(ks, d + pos, nlen, name, sizeof(name));
        pos += nlen;

        if (name[0] == '\0')
            continue;

        char sym_type = name[0];
        const char *sym_name = name + 1;
        uint64_t addr = get_sym_addr(ks, i);

        if (ks->addrs_off != 0)
            fprintf(out, "%016lx %c %s\n", (unsigned long)addr, sym_type, sym_name);
        else
            fprintf(out, "%c %s\n", sym_type, sym_name);

        count++;
    }

    fprintf(stderr, "Extracted %zu symbols\n", count);
}

/* ---- Linux banner ---- */

static void print_linux_banner(const uint8_t *data, size_t size)
{
    const uint8_t *p = memmem(data, size, "Linux version ", 14);
    if (p) {
        size_t remaining = size - (p - data);
        size_t len = 0;
        while (len < remaining && len < 256 && p[len] != '\0' && p[len] != '\n')
            len++;
        fprintf(stderr, "Kernel: %.*s\n", (int)len, p);
    }
}

/* ---- Main ---- */

static int usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s\n"
        "\t-i|--input <boot.img>           boot image input\n"
        "\t-k|--kernel <kernel_image>      raw kernel input\n"
        "\t[ -o|--output <output_file> ]   output file (default: stdout)\n"
        "\t[ --ptr-size <4|8> ]            target pointer size (default: 8)\n",
        prog);
    return 1;
}

int main(int argc, char **argv)
{
    const char *input_boot = NULL;
    const char *input_kernel = NULL;
    const char *output_file = NULL;
    int ptr_size = 8;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-i") || !strcmp(argv[i], "--input")) && i + 1 < argc) {
            input_boot = argv[++i];
        } else if ((!strcmp(argv[i], "-k") || !strcmp(argv[i], "--kernel")) && i + 1 < argc) {
            input_kernel = argv[++i];
        } else if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) && i + 1 < argc) {
            output_file = argv[++i];
        } else if (!strcmp(argv[i], "--ptr-size") && i + 1 < argc) {
            ptr_size = atoi(argv[++i]);
        } else {
            return usage(argv[0]);
        }
    }

    if (!input_boot && !input_kernel) {
        fprintf(stderr, "error: specify -i (boot.img) or -k (raw kernel)\n");
        return usage(argv[0]);
    }

    /* Load input */
    uint8_t *raw_kernel = NULL;
    size_t raw_kernel_size = 0;

    if (input_boot) {
        size_t img_size;
        uint8_t *img = load_file(input_boot, &img_size);
        if (!img)
            return 1;

        raw_kernel = extract_kernel_from_bootimg(img, img_size, &raw_kernel_size);
        free(img);
        if (!raw_kernel) {
            fprintf(stderr, "error: failed to extract kernel from boot image\n");
            return 1;
        }
    } else {
        raw_kernel = load_file(input_kernel, &raw_kernel_size);
        if (!raw_kernel)
            return 1;
        fprintf(stderr, "Loaded kernel: %zu bytes\n", raw_kernel_size);
    }

    /* Decompress if needed */
    size_t kern_size;
    uint8_t *kernel = decompress_kernel(raw_kernel, raw_kernel_size, &kern_size);
    free(raw_kernel);
    if (!kernel) {
        fprintf(stderr, "error: failed to decompress kernel\n");
        return 1;
    }

    print_linux_banner(kernel, kern_size);

    /* Find kallsyms */
    struct kallsyms ks = {0};
    ks.data = kernel;
    ks.size = kern_size;
    ks.ptr_size = ptr_size;

    if (!find_token_table(&ks)) {
        fprintf(stderr, "error: kallsyms token_table not found\n");
        free(kernel);
        return 1;
    }

    if (!find_markers(&ks)) {
        fprintf(stderr, "error: kallsyms markers not found\n");
        free(kernel);
        return 1;
    }

    if (!find_num_syms_and_names(&ks)) {
        fprintf(stderr, "error: kallsyms num_syms/names not found\n");
        free(kernel);
        return 1;
    }

    find_addresses(&ks);

    /* Output */
    FILE *out = stdout;
    if (output_file) {
        out = fopen(output_file, "w");
        if (!out) {
            fprintf(stderr, "error: cannot open '%s': %s\n", output_file, strerror(errno));
            free(kernel);
            return 1;
        }
    }

    print_kallsyms(&ks, out);

    if (output_file)
        fclose(out);

    free(kernel);
    return 0;
}
