#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>

#define BOOT_MAGIC "ANDROID!"
#define VENDOR_BOOT_MAGIC "VNDRBOOT"
#define LZ4_LEGACY_MAGIC 0x184C2102
#define ARM64_IMAGE_MAGIC 0x644D5241

static inline uint32_t get_u32(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* --- Core Extraction Logic with Carve Fix --- */
static uint8_t *extract_kernel(const uint8_t *img, size_t img_sz, size_t *out_sz) {
    size_t k_off = 0; 
    uint64_t k_sz = 0;

    if (img_sz < 64) return NULL;

    if (memcmp(img, BOOT_MAGIC, 8) == 0) {
        uint32_t ver = get_u32(img + 40);
        k_sz = get_u32(img + 8);
        uint32_t p_sz = (ver >= 3) ? 4096 : get_u32(img + 36);
        k_off = p_sz;
        fprintf(stderr, "[+] Detected Standard Boot Image v%u\n", ver);
    } 
    else if (memcmp(img, VENDOR_BOOT_MAGIC, 8) == 0) {
        uint32_t p_sz = get_u32(img + 12);
        k_sz = get_u32(img + 16);
        k_off = p_sz; 
        fprintf(stderr, "[+] Detected GKI Vendor Kernel Boot\n");
    } 
    else {
        for (size_t i = 0; i < img_sz - 64; i += 4) {
            if (get_u32(img + i + 0x38) == ARM64_IMAGE_MAGIC) {
                k_off = i; 
                k_sz = (uint64_t)(img_sz - i);
                fprintf(stderr, "[+] Carved ARM64 Kernel at offset 0x%zx\n", i);
                break;
            }
        }
    }

    if (k_off >= img_sz) {
        fprintf(stderr, "[-] Error: Kernel offset outside file bounds.\n");
        return NULL;
    }

    /* Carve Fix: If header claims more than file has, take what's left */
    if (k_sz == 0 || k_off + k_sz > img_sz) {
        fprintf(stderr, "[!] Warning: Header claims %lu bytes, but file is %zu. Carving available data.\n", 
                (unsigned long)k_sz, img_sz);
        k_sz = img_sz - k_off;
    }

    uint8_t *res = malloc(k_sz);
    if (!res) return NULL;
    memcpy(res, img + k_off, k_sz);
    *out_sz = (size_t)k_sz;
    return res;
}

/* --- LZ4 Legacy Decompressor --- */
static int lz4_unblock(const uint8_t *src, int src_len, uint8_t *dst, int dst_cap) {
    const uint8_t *ip = src, *ie = src + src_len;
    uint8_t *op = dst, *oe = dst + dst_cap;
    while (ip < ie) {
        unsigned t = *ip++;
        unsigned L = t >> 4;
        if (L == 15) { if (ip >= ie) return -1; unsigned s; do { s = *ip++; L += s; } while (s == 255); }
        if (op + L > oe || ip + L > ie) return -1;
        memcpy(op, ip, L); ip += L; op += L;
        if (ip >= ie) break;
        unsigned off = ip[0] | (ip[1] << 8); ip += 2;
        if (off == 0 || (op - dst) < off) return -1;
        unsigned M = (t & 0xf) + 4;
        if ((t & 0xf) == 15) { if (ip >= ie) return -1; unsigned s; do { s = *ip++; M += s; } while (s == 255); }
        uint8_t *ref = op - off;
        for (unsigned i = 0; i < M; i++) { if (op >= oe) return -1; *op++ = *ref++; }
    }
    return (int)(op - dst);
}

static uint8_t *decompress_lz4(const uint8_t *src, size_t src_sz, size_t *out_sz) {
    if (src_sz < 8 || get_u32(src) != LZ4_LEGACY_MAGIC) return NULL;
    size_t cap = 512 * 1024 * 1024; /* 512MB Buffer */
    uint8_t *out = malloc(cap);
    if (!out) return NULL;
    size_t total = 0, off = 4;
    while (off + 4 <= src_sz) {
        uint32_t bsz = get_u32(src + off); off += 4;
        if (bsz == 0 || off + bsz > src_sz) break;
        int dec = lz4_unblock(src + off, bsz, out + total, (int)(cap - total));
        if (dec < 0) break;
        total += dec; off += bsz;
    }
    if (total == 0) { free(out); return NULL; }
    *out_sz = total;
    return out;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        printf("Usage: %s -i <vendor_kernel_boot.img> -o <kernel_output>\n", argv[0]);
        return 1;
    }

    char *in_path = NULL, *out_path = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) in_path = argv[++i];
        else if (strcmp(argv[i], "-o") == 0) out_path = argv[++i];
    }

    FILE *f = fopen(in_path, "rb");
    if (!f) { perror("fopen input"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t f_sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *f_buf = malloc(f_sz);
    if (!f_buf) return 1;
    fread(f_buf, 1, f_sz, f);
    fclose(f);

    size_t k_sz;
    uint8_t *k_buf = extract_kernel(f_buf, f_sz, &k_sz);
    if (!k_buf) { free(f_buf); return 1; }

    /* Try LZ4 Decompression */
    size_t raw_sz;
    uint8_t *raw_buf = decompress_lz4(k_buf, k_sz, &raw_sz);

    FILE *out = fopen(out_path, "wb");
    if (!out) { perror("fopen output"); return 1; }

    if (raw_buf) {
        fprintf(stderr, "[+] Success: Decompressed LZ4 kernel (%zu bytes)\n", raw_sz);
        fwrite(raw_buf, 1, raw_sz, out);
        free(raw_buf);
    } else if (k_sz > 2 && k_buf[0] == 0x1f && k_buf[1] == 0x8b) {
        fprintf(stderr, "[!] Detected Gzip compression. Please use 'gunzip' on the output.\n");
        fwrite(k_buf, 1, k_sz, out);
    } else {
        fprintf(stderr, "[!] No compression detected, saving raw extraction (%zu bytes)\n", k_sz);
        fwrite(k_buf, 1, k_sz, out);
    }

    fclose(out);
    free(k_buf);
    free(f_buf);
    printf("Done! Output saved to: %s\n", out_path);
    return 0;
}
