#include "apk_signature.h"
#include "../utils/syscall_utils.h"
#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>

#define LOG_TAG "SentryTag"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

#ifndef O_RDONLY
#define O_RDONLY 0
#endif
#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

/* ============================ SHA-256 ============================ *
 * 自带实现，避免依赖 libcrypto/Java（Java 路径可被 hook）。           */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(sha256_ctx *c, const uint8_t *d) {
    uint32_t m[64], a,b,e_,f,g,h,t1,t2,cc,dd;
    for (int i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = (uint32_t)d[j] << 24 | (uint32_t)d[j+1] << 16 | (uint32_t)d[j+2] << 8 | (uint32_t)d[j+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(m[i-15],7) ^ ROR(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = ROR(m[i-2],17) ^ ROR(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; dd=c->state[3];
    e_=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROR(e_,6) ^ ROR(e_,11) ^ ROR(e_,25);
        uint32_t ch = (e_ & f) ^ ((~e_) & g);
        t1 = h + S1 + ch + K256[i] + m[i];
        uint32_t S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h=g; g=f; f=e_; e_=dd + t1; dd=cc; cc=b; b=a; a=t1 + t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=dd;
    c->state[4]+=e_; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

static void sha256_init(sha256_ctx *c) {
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85; c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c; c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *c, const uint8_t *d, size_t len) {
    for (size_t i = 0; i < len; i++) {
        c->data[c->datalen++] = d[i];
        if (c->datalen == 64) {
            sha256_transform(c, c->data);
            c->bitlen += 512;
            c->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t *hash) {
    uint32_t i = c->datalen;
    c->data[i++] = 0x80;
    if (c->datalen < 56) {
        while (i < 56) c->data[i++] = 0;
    } else {
        while (i < 64) c->data[i++] = 0;
        sha256_transform(c, c->data);
        for (uint32_t j = 0; j < 56; j++) c->data[j] = 0;
    }
    c->bitlen += (uint64_t)c->datalen * 8;
    for (int j = 7; j >= 0; j--) c->data[56 + (7 - j)] = (uint8_t)(c->bitlen >> (j * 8));
    sha256_transform(c, c->data);
    for (int j = 0; j < 4; j++)
        for (int k = 0; k < 8; k++)
            hash[k * 4 + j] = (uint8_t)(c->state[k] >> (24 - j * 8));
}

static void to_hex_lower(const uint8_t *in, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i * 2] = H[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = H[in[i] & 0xF];
    }
    out[n * 2] = '\0';
}

/* ============================ ZIP / APK Sig Block 解析 ============================ */

static inline uint32_t rd_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline uint64_t rd_u64le(const uint8_t *p) {
    uint64_t lo = rd_u32le(p), hi = rd_u32le(p + 4);
    return lo | (hi << 32);
}

#define EOCD_SIG       0x06054b50u
#define APK_SIG_V2_ID  0x7109871au
#define APK_SIG_V3_ID  0xf05368c0u
#define APK_SIG_V3_1_ID 0x1b93ad61u   /* v3.1，结构与 v3 同 */
#define EOCD_MAX_SCAN  (65557)        /* 22 字节 EOCD + 最大 65535 注释 */
#define SIG_BLOCK_CAP  (8 * 1024 * 1024)  /* 签名块上限 8MB，超出视为异常 */
#define APK_SIG_MAGIC  "APK Sig Block 42"

static off_t file_size_via_lseek(int fd) {
    return (off_t)my_lseek(fd, 0, SEEK_END);
}

/* 读取 [off, off+len) 到 buf；成功返回实际读取字节数（应 == len），否则 -1 */
static ssize_t read_at(int fd, off_t off, void *buf, size_t len) {
    if (my_lseek(fd, off, SEEK_SET) != (ssize_t)off) return -1;
    size_t got = 0;
    uint8_t *p = (uint8_t *)buf;
    while (got < len) {
        ssize_t r = my_read(fd, p + got, len - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

/* 从 v2/v3 签名块的 value 中取首签名者首证书 DER，写指针/长度（指向 val 内部，不拷贝） */
static int extract_first_cert(const uint8_t *val, uint32_t val_len,
                              const uint8_t **out_cert, uint32_t *out_cert_len) {
    /* 结构（全部 uint32-LE 长度前缀）：
     * value = u32 len-prefixed sequence of signers
     *   signer = u32 len + { signed_data(u32 len+..), signatures(u32 len+..), publickey(u32 len+..) }
     *   signed_data = u32 len + { digests(u32 len+..), certificates(u32 len+..), ... }
     *   certificates = u32 len + { cert(u32 len + DER), ... } */
    uint32_t off = 0;
    #define NEED(n) do { if (off + (n) > val_len) return -1; } while (0)

    NEED(4); uint32_t signers_len = rd_u32le(val + off); off += 4;
    if (signers_len == 0 || off + signers_len > val_len) return -1;

    NEED(4); uint32_t signer_len = rd_u32le(val + off); off += 4;
    if (signer_len < 4 || off + signer_len > val_len) return -1;
    uint32_t signer_base = off;             /* signer 内容起点 */
    uint32_t signer_end = off + signer_len;

    /* signed_data（signer 的第一个子结构） */
    if (signer_base + 4 > signer_end) return -1;
    uint32_t sd_len = rd_u32le(val + signer_base);
    uint32_t sd_base = signer_base + 4;
    if (sd_len < 4 || sd_base + sd_len > signer_end) return -1;
    uint32_t sd_end = sd_base + sd_len;

    /* signed_data 内：digests（先跳过），certificates */
    uint32_t c = sd_base;
    if (c + 4 > sd_end) return -1;
    uint32_t digests_len = rd_u32le(val + c); c += 4;
    if (c + digests_len > sd_end) return -1;
    c += digests_len;                       /* 跳过 digests */

    if (c + 4 > sd_end) return -1;
    uint32_t certs_len = rd_u32le(val + c); c += 4;
    if (certs_len < 4 || c + certs_len > sd_end) return -1;
    uint32_t certs_end = c + certs_len;

    /* certificates 内首证书 */
    if (c + 4 > certs_end) return -1;
    uint32_t cert_len = rd_u32le(val + c); c += 4;
    if (cert_len == 0 || c + cert_len > certs_end) return -1;

    *out_cert = val + c;
    *out_cert_len = cert_len;
    return 0;
    #undef NEED
}

int apk_get_signing_cert_sha256(const char *apk_path, char *out_hex, size_t out_len) {
    if (!apk_path || !out_hex || out_len < 65) return -1;
    out_hex[0] = '\0';

    int fd = my_open(apk_path, O_RDONLY, 0);
    if (fd < 0) { LOGD("[APKsig] open failed: %s", apk_path); return -1; }

    int ret = -1;
    uint8_t *tail = nullptr;
    uint8_t *block = nullptr;

    off_t fsize = file_size_via_lseek(fd);
    if (fsize < 64) goto done;

    /* 1. 读文件尾，定位 EOCD（0x06054b50） */
    {
        size_t scan = (size_t)(fsize < EOCD_MAX_SCAN ? fsize : EOCD_MAX_SCAN);
        tail = (uint8_t *)malloc(scan);
        if (!tail) goto done;
        off_t tail_off = fsize - (off_t)scan;
        if (read_at(fd, tail_off, tail, scan) != (ssize_t)scan) goto done;

        long eocd = -1;
        /* 从后往前找 EOCD（至少需 22 字节 EOCD 头） */
        for (long i = (long)scan - 22; i >= 0; i--) {
            if (rd_u32le(tail + i) == EOCD_SIG) { eocd = i; break; }
        }
        if (eocd < 0) { LOGD("[APKsig] EOCD not found"); goto done; }

        uint32_t cd_offset = rd_u32le(tail + eocd + 16);
        if (cd_offset == 0xFFFFFFFFu) { LOGD("[APKsig] ZIP64 unsupported"); goto done; }  /* APK 不用 ZIP64 */
        if ((off_t)cd_offset > fsize || cd_offset < 32) goto done;

        /* 2. APK Sig Block 位于 CD 之前：尾部 = [u64 S2][16B magic] */
        uint8_t trailer[24];
        if (read_at(fd, (off_t)cd_offset - 24, trailer, 24) != 24) goto done;
        if (my_memcmp(trailer + 8, APK_SIG_MAGIC, 16) != 0) {
            LOGD("[APKsig] no APK Sig Block magic (v1-only or unsigned?)");
            goto done;
        }
        uint64_t s2 = rd_u64le(trailer);
        if (s2 < 24 || s2 > SIG_BLOCK_CAP || (off_t)s2 > (off_t)cd_offset) goto done;

        /* pairs 区间 = [cd_offset - s2, cd_offset - 24)，长度 s2 - 24 */
        uint32_t pairs_len = (uint32_t)(s2 - 24);
        off_t pairs_off = (off_t)cd_offset - (off_t)s2;
        if (pairs_off < 0) goto done;
        block = (uint8_t *)malloc(pairs_len);
        if (!block) goto done;
        if (read_at(fd, pairs_off, block, pairs_len) != (ssize_t)pairs_len) goto done;

        /* 3. 遍历 ID-value 对，找 v2 / v3 / v3.1 */
        const uint8_t *v2v3_val = nullptr;
        uint32_t v2v3_len = 0;
        uint64_t pc = 0;
        while (pc + 12 <= pairs_len) {
            uint64_t pair_len = rd_u64le(block + pc);
            if (pair_len < 4 || pc + 8 + pair_len > pairs_len) break;
            uint32_t id = rd_u32le(block + pc + 8);
            const uint8_t *value = block + pc + 12;
            uint32_t value_len = (uint32_t)(pair_len - 4);
            if (id == APK_SIG_V3_ID || id == APK_SIG_V3_1_ID) {
                v2v3_val = value; v2v3_len = value_len; break;  /* v3 优先 */
            }
            if (id == APK_SIG_V2_ID && v2v3_val == nullptr) {
                v2v3_val = value; v2v3_len = value_len;          /* 暂存 v2，继续找 v3 */
            }
            pc += 8 + pair_len;
        }
        if (!v2v3_val) { LOGD("[APKsig] no v2/v3 signer block"); goto done; }

        /* 4. 取首证书 DER，SHA-256 */
        const uint8_t *cert = nullptr;
        uint32_t cert_len = 0;
        if (extract_first_cert(v2v3_val, v2v3_len, &cert, &cert_len) != 0) {
            LOGD("[APKsig] cert parse failed");
            goto done;
        }
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, cert, cert_len);
        uint8_t digest[32];
        sha256_final(&ctx, digest);
        to_hex_lower(digest, 32, out_hex);
        LOGD("[APKsig] file cert sha256=%s (cert_len=%u)", out_hex, cert_len);
        ret = 0;
    }

done:
    if (tail) free(tail);
    if (block) free(block);
    my_close(fd);
    return ret;
}
