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

/**
 * APK fd / maps inode 一致性（揭穿 open(base.apk) 文件重定向，参考看雪 #9 / testapp c23）。
 *
 * 过签运行时常用 seccomp / GOT 把 open(base.apk) 重定向到替身 APK，让所有取证通道读到
 * 原始签名。本函数 open(apk_path) 后 fstat 取 st_ino，再读 /proc/self/maps 解析真正
 * mmap 进来的 base.apk 映射 inode：除非绕过框架同时改写 maps，两者必然不一致。
 *
 * @param apk_path 已安装 APK 绝对路径（ApplicationInfo.sourceDir）
 * @return 1 一致（正常）；0 inode 不一致（fd 被重定向，DANGER）；<0 无法判定（应跳过）
 */
int apk_fd_inode_consistent(const char *apk_path);

/**
 * seccomp prctl 与 /proc/self/status 一致性（揭穿伪造 status 隐藏过滤器，参考 testapp c20）。
 *
 * 每个 Android App 都被 seccomp 沙箱（mode=2），故"有无 seccomp"本身不是篡改信号；
 * 但绕过框架若把 status 文件读重定向到伪造内容（隐藏自身过滤器），prctl(内核真值，
 * 未被白名单的调用方改不了)就会与 status 字段不一致。
 *
 * @return 1 一致（正常）；0 不一致（status 被伪造，DANGER）；<0 无法判定（应跳过）
 */
int seccomp_prctl_status_consistent(void);

#ifdef __cplusplus
}
#endif

#endif /* APK_SIGNATURE_H */
