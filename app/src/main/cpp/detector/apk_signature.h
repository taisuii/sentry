#ifndef APK_SIGNATURE_H
#define APK_SIGNATURE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 直接从 APK 文件解析 v2/v3 签名块，取首签名者首证书的 SHA-256（小写十六进制）。
 *
 * 绕开 PackageManager（可被 CorePatch/签名伪装类模块 hook 后返回伪造的原始签名），
 * 用 syscall 直读文件、native SHA-256，给"防改包 + 反签名伪装"提供文件级真值。
 *
 * @param apk_path 已安装 APK 的绝对路径（来自 ApplicationInfo.sourceDir）
 * @param out_hex  输出缓冲，写入 64 字符小写 hex + '\0'（需 >= 65 字节）
 * @param out_len  out_hex 容量
 * @return 0 成功；-1 失败（文件不可读 / 非 ZIP / 无 v2-v3 签名块 / 解析越界）
 */
int apk_get_signing_cert_sha256(const char *apk_path, char *out_hex, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* APK_SIGNATURE_H */
