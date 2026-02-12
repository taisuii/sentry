#ifndef XPOSED_DETECTOR_H
#define XPOSED_DETECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 检测 Xposed 特征路径与进程 fd（如 linjector）。
 * 使用 syscall（my_access）绕过 libc hook。
 * details 填入发现项，返回发现数量；任意发现即表示存在 Xposed 相关环境。
 */
int get_xposed_path_and_fd_details(char (*details)[256], int max_details);

#ifdef __cplusplus
}
#endif

#endif // XPOSED_DETECTOR_H
