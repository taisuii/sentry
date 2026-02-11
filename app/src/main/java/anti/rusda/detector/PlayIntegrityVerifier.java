package anti.rusda.detector;

/**
 * 服务端 Play Integrity token 验证接口。
 * 客户端获取 token 后，调用方注入实现此接口，将 token 发送至服务端并用 Google API 校验。
 * 返回 STATUS_NORMAL / STATUS_WARNING / STATUS_DANGER。
 */
public interface PlayIntegrityVerifier {
    /**
     * @param token Play Integrity API 返回的 token
     * @return DetectionResult.STATUS_NORMAL / STATUS_WARNING / STATUS_DANGER
     */
    int verifyToken(String token);
}
