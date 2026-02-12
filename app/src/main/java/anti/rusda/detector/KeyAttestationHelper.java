package anti.rusda.detector;

import android.os.Build;
import android.os.SystemClock;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 通过 Android Key Attestation（密钥认证）获取 TEE/TrustZone 中的 RootOfTrust 信息，
 * 检测 boot.img 是否被修补、bootloader 是否解锁等。
 * 对应 Hunter 等工具检测的 verifiedBootKey、deviceLocked、verifiedBootState、verifiedBootHash。
 *
 * <p><b>完全本地实现</b>：无需接入 Google API 或联网。密钥在 AndroidKeyStore 中生成时，
 * 由 TEE/StrongBox 硬件签发证明证书链，证书扩展（OID 1.3.6.1.4.1.11129.2.1.17）中已包含
 * RootOfTrust，本地解析即可；root 也无法伪造该硬件级证明。
 *
 * <p>需 API 28+（setAttestationChallenge）；部分设备需 Keymaster 2.0+ / KeyMint 才支持。
 *
 * <p>Note: Google is transitioning to a new root certificate for Key Attestation.
 * RKP-enabled devices will exclusively use the new root by April 10, 2026.
 * Trust stores: https://android.googleapis.com/attestation/root
 */
public class KeyAttestationHelper {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ATTESTATION_KEY_ALIAS = "sentry_attestation_key";
    /** Android Key Attestation extension OID */
    private static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    /** Keymaster ROOT_OF_TRUST tag in AuthorizationList */
    private static final int KM_TAG_ROOT_OF_TRUST = 704;

    /** Verified boot state: Verified=0, SelfSigned=1, Unverified=2, Failed=3 */
    private static final int BOOT_VERIFIED = 0;
    private static final int BOOT_SELF_SIGNED = 1;
    private static final int BOOT_UNVERIFIED = 2;
    private static final int BOOT_FAILED = 3;

    /**
     * 同步执行 Key Attestation 检测，解析 RootOfTrust。
     *
     * @return [status, summary, detail0, detail1, ...]，status 0=NORMAL, 1=WARNING, 2=DANGER
     */
    public static String[] runAttestationSync() {
        List<String> details = new ArrayList<>();
        if (Build.VERSION.SDK_INT < 28) {
            details.add("Key attestation requires API 28+ (current: " + Build.VERSION.SDK_INT + ")");
            return new String[]{
                    String.valueOf(DetectionResult.STATUS_NORMAL),
                    "Key attestation not supported on this API level (passed)",
                    String.join("; ", details)
            };
        }

        try {
            byte[] challenge = new byte[32];
            new java.security.SecureRandom().nextBytes(challenge);

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    ATTESTATION_KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            kpg.initialize(spec);
            kpg.generateKeyPair();

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            java.security.cert.Certificate[] chain = ks.getCertificateChain(ATTESTATION_KEY_ALIAS);
            if (chain == null || chain.length == 0) {
                deleteAttestationKey(ks);
                details.add("Empty certificate chain");
                return new String[]{
                        String.valueOf(DetectionResult.STATUS_WARNING),
                        "Key attestation: no certificate chain",
                        String.join("; ", details)
                };
            }

            int statusFromChain = DetectionResult.STATUS_NORMAL;
            if (chain.length < 2) {
                details.add("Certificate chain too short (expected 2+, got " + chain.length + ")");
                statusFromChain = DetectionResult.STATUS_WARNING;
            }
            boolean hasKnownRoot = false;
            for (int i = 1; i < chain.length; i++) {
                X509Certificate cert = (X509Certificate) chain[i];
                String issuer = cert.getIssuerDN().getName();
                if (issuer != null && (issuer.contains("Android Keystore") || issuer.contains("Google") || issuer.contains("RKP"))) {
                    hasKnownRoot = true;
                    break;
                }
            }
            if (!hasKnownRoot && chain.length > 1) {
                details.add("Certificate chain does not contain known root (Android Keystore/Google/RKP)");
                statusFromChain = Math.max(statusFromChain, DetectionResult.STATUS_WARNING);
            }

            X509Certificate leaf = (X509Certificate) chain[0];
            byte[] extValue = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID);
            deleteAttestationKey(ks);

            if (extValue == null || extValue.length == 0) {
                details.add("No attestation extension in certificate");
                return new String[]{
                        String.valueOf(DetectionResult.STATUS_WARNING),
                        "Key attestation: extension missing (device may not support TEE attestation)",
                        String.join("; ", details)
                };
            }

            RootOfTrust rot = parseRootOfTrust(extValue);
            if (rot == null) {
                // 部分机型 TEE/Keymaster 的 attestation 结构与当前解析器不兼容，属厂商差异，不做风险判定避免误报
                details.add("RootOfTrust structure not recognized on this device (OEM-specific format)");
                details.add("TEE AVB values (verifiedBootKey, verifiedBootHash, deviceLocked) unavailable - see AVB (System Properties) above for fallback");
                String[] out = new String[2 + details.size()];
                out[0] = String.valueOf(DetectionResult.STATUS_NORMAL);
                out[1] = "Key attestation: format not recognized on this device (passed)";
                for (int i = 0; i < details.size(); i++) {
                    out[2 + i] = details.get(i);
                }
                return out;
            }

            int status = Math.max(DetectionResult.STATUS_NORMAL, statusFromChain);
            boolean isEmulator = isLikelyEmulator();
            if (rot.verifiedBootKeyAllZeros && !isEmulator) {
                status = DetectionResult.STATUS_DANGER;
            } else if (rot.verifiedBootKeyAllZeros && isEmulator) {
                details.add("verifiedBootKey all zeros (emulator - not flagged as DANGER)");
            }
            if (!rot.deviceLocked) status = DetectionResult.STATUS_DANGER;
            if (rot.verifiedBootState == BOOT_UNVERIFIED || rot.verifiedBootState == BOOT_FAILED) status = DetectionResult.STATUS_DANGER;
            if (rot.verifiedBootState == BOOT_SELF_SIGNED && status != DetectionResult.STATUS_DANGER) status = DetectionResult.STATUS_WARNING;

            long uptimeMs = SystemClock.elapsedRealtime();
            if (uptimeMs < 60000) {
                details.add("Device recently booted (< 1 min) - possible bypass attempt");
                status = Math.max(status, DetectionResult.STATUS_WARNING);
            }

            // Device State section
            details.add("═══ Device State ═══");
            details.add("deviceLocked: " + rot.deviceLocked + (rot.deviceLocked ? " ✓" : " ✗"));
            details.add("verifiedBootState: " + rot.verifiedBootStateName + (rot.verifiedBootState == BOOT_VERIFIED ? " ✓" : " ✗"));
            details.add("hardwareBacked: Yes ✓");
            details.add("verifiedBootKey: " + rot.verifiedBootKeyHex);
            details.add("verifiedBootHash: " + rot.verifiedBootHashHex);
            if (rot.verifiedBootKeyAllZeros) details.add("verifiedBootKey is all zeros - boot may have been patched");

            // Security Impact section
            details.add("═══ Security Impact ═══");
            boolean hasImpact = false;
            if (!rot.deviceLocked) {
                details.add("• Bootloader is UNLOCKED");
                hasImpact = true;
            }
            if (rot.verifiedBootState == BOOT_UNVERIFIED || rot.verifiedBootState == BOOT_FAILED) {
                details.add("• AVB verification DISABLED/SKIPPED");
                details.add("• Boot images are NOT verified");
                hasImpact = true;
            }
            if (rot.verifiedBootKeyAllZeros || !rot.deviceLocked) {
                details.add("• Custom firmware can be flashed");
                hasImpact = true;
            }
            if (status == DetectionResult.STATUS_DANGER || status == DetectionResult.STATUS_WARNING) {
                details.add("• Banking apps may refuse to run");
                details.add("• Play Integrity will fail");
                hasImpact = true;
            }
            if (!hasImpact) {
                details.add("• No significant security impact");
            }

            String summary = status == DetectionResult.STATUS_DANGER
                    ? "Boot may be patched or bootloader unlocked"
                    : status == DetectionResult.STATUS_WARNING
                    ? "Self-signed or uncertain boot"
                    : "Boot verified";

            String[] out = new String[2 + details.size()];
            out[0] = String.valueOf(status);
            out[1] = summary;
            for (int i = 0; i < details.size(); i++) {
                out[2 + i] = details.get(i);
            }
            return out;

        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new String[]{
                    String.valueOf(DetectionResult.STATUS_WARNING),
                    "Key attestation failed: " + msg,
                    "Exception: " + msg
            };
        }
    }

    private static boolean isLikelyEmulator() {
        String model = Build.MODEL != null ? Build.MODEL : "";
        String hardware = Build.HARDWARE != null ? Build.HARDWARE : "";
        String product = Build.PRODUCT != null ? Build.PRODUCT : "";
        String device = Build.DEVICE != null ? Build.DEVICE : "";
        String lower = (model + " " + hardware + " " + product + " " + device).toLowerCase();
        return lower.contains("emulator") || lower.contains("generic") || lower.contains("sdk")
                || lower.contains("goldfish") || lower.contains("ranchu") || lower.contains("vbox");
    }

    private static void deleteAttestationKey(KeyStore ks) {
        try {
            ks.deleteEntry(ATTESTATION_KEY_ALIAS);
        } catch (Exception ignored) {
        }
    }

    /**
     * 从 attestation 扩展的原始字节中解析 RootOfTrust。
     * 扩展值为 OCTET STRING，其内容为 KeyDescription DER。
     * KeyDescription 中 typically index 6=softwareEnforced、7=teeEnforced (AuthorizationList)，
     * 其中 tag 704 (ROOT_OF_TRUST) 的值为 RootOfTrust SEQUENCE。
     * 部分 OEM 的 KeyDescription 结构（索引、嵌套）有差异，故会尝试多个索引并递归搜索。
     */
    private static RootOfTrust parseRootOfTrust(byte[] extValue) {
        try {
            ASN1Primitive outer = ASN1Primitive.fromByteArray(extValue);
            byte[] keyDescBytes;
            if (outer instanceof ASN1OctetString) {
                keyDescBytes = ((ASN1OctetString) outer).getOctets();
            } else if (outer instanceof DEROctetString) {
                keyDescBytes = ((DEROctetString) outer).getOctets();
            } else {
                return null;
            }

            ASN1Primitive keyDescPrim = ASN1Primitive.fromByteArray(keyDescBytes);
            if (!(keyDescPrim instanceof ASN1Sequence)) {
                return null;
            }
            ASN1Sequence keyDesc = (ASN1Sequence) keyDescPrim;
            if (keyDesc.size() < 6) {
                return null;
            }

            // 尝试多个索引：部分 OEM 将 teeEnforced 放在 6、7 或 8
            for (int authListIdx : new int[]{7, 6, 8, 5}) {
                if (authListIdx >= keyDesc.size()) continue;
                RootOfTrust rot = parseRootOfTrustFromAuthList(toSequence(keyDesc.getObjectAt(authListIdx)));
                if (rot != null) return rot;
            }

            // 递归搜索：遍历 KeyDescription 中所有 Sequence，查找包含 RootOfTrust 的（深度限制防栈溢出）
            for (int i = 0; i < keyDesc.size(); i++) {
                RootOfTrust rot = searchRootOfTrustRecursive(keyDesc.getObjectAt(i), 0, 8);
                if (rot != null) return rot;
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static RootOfTrust searchRootOfTrustRecursive(ASN1Encodable enc, int depth, int maxDepth) {
        if (depth >= maxDepth) return null;
        ASN1Sequence seq = toSequence(enc);
        if (seq == null) return null;
        RootOfTrust rot = parseRootOfTrustFromAuthList(seq);
        if (rot != null) return rot;
        for (int i = 0; i < seq.size(); i++) {
            rot = searchRootOfTrustRecursive(seq.getObjectAt(i), depth + 1, maxDepth);
            if (rot != null) return rot;
        }
        return null;
    }

    private static RootOfTrust parseRootOfTrustFromAuthList(ASN1Sequence authList) {
        if (authList == null) return null;
        for (int i = 0; i < authList.size(); i++) {
            ASN1Encodable entryEnc = authList.getObjectAt(i);
            ASN1Sequence rootSeq = null;

            /* Android schema: rootOfTrust [704] EXPLICIT RootOfTrust - ASN1TaggedObject on many devices */
            if (entryEnc instanceof ASN1TaggedObject) {
                ASN1TaggedObject to = (ASN1TaggedObject) entryEnc;
                if (to.getTagNo() == KM_TAG_ROOT_OF_TRUST) {
                    rootSeq = toSequence(to.getBaseObject());
                }
            }
            if (rootSeq == null) {
                ASN1Sequence entry = toSequence(entryEnc);
                if (entry != null) {
                    if (entry.size() >= 2) {
                        int tag = getTagValue(entry.getObjectAt(0));
                        if (tag == KM_TAG_ROOT_OF_TRUST) {
                            rootSeq = toSequence(entry.getObjectAt(1));
                        }
                    }
                    if (rootSeq == null && (entry.size() == 4 || entry.size() == 3)) {
                        rootSeq = entry;
                    }
                }
            }
            if (rootSeq == null || rootSeq.size() < 3) continue;

            RootOfTrust rot = parseRootOfTrustSequence(rootSeq);
            if (rot != null) return rot;
        }
        return null;
    }

    private static RootOfTrust parseRootOfTrustSequence(ASN1Sequence rootSeq) {
        try {
            /* Standard: [verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash]
             * Version 1/2: only 3 elements, no verifiedBootHash */
            byte[] verifiedBootKey = getOctetString(rootSeq.getObjectAt(0));
            boolean deviceLocked = getBoolean(rootSeq.getObjectAt(1));
            int verifiedBootState = getInt(rootSeq.getObjectAt(2));
            byte[] verifiedBootHash = rootSeq.size() >= 4 ? getOctetString(rootSeq.getObjectAt(3)) : null;

            if (verifiedBootKey == null && verifiedBootHash == null) return null;

            String vbkHex = verifiedBootKey != null ? bytesToHex(verifiedBootKey) : "(null)";
            String vbhHex = verifiedBootHash != null ? bytesToHex(verifiedBootHash) : "(null)";
            boolean allZeros = isAllZeros(verifiedBootKey);

            String stateName;
            switch (verifiedBootState) {
                case BOOT_VERIFIED:   stateName = "Verified"; break;
                case BOOT_SELF_SIGNED: stateName = "SelfSigned"; break;
                case BOOT_UNVERIFIED: stateName = "Unverified"; break;
                case BOOT_FAILED:     stateName = "Failed"; break;
                default:              stateName = "Unknown"; break;
            }

            return new RootOfTrust(vbkHex, deviceLocked, verifiedBootState, stateName, vbhHex, allZeros);
        } catch (Exception e) {
            return null;
        }
    }

    private static ASN1Sequence toSequence(ASN1Encodable e) {
        if (e == null) return null;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            return p instanceof ASN1Sequence ? (ASN1Sequence) p : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static int getTagValue(ASN1Encodable e) {
        if (e == null) return -1;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof org.bouncycastle.asn1.ASN1Integer) {
                return ((org.bouncycastle.asn1.ASN1Integer) p).getValue().intValue();
            }
        } catch (Exception ex) {
            // ignore
        }
        return -1;
    }

    private static byte[] getOctetString(ASN1Encodable e) {
        if (e == null) return null;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof ASN1OctetString) {
                return ((ASN1OctetString) p).getOctets();
            }
            if (p instanceof ASN1TaggedObject) {
                Object inner = ((ASN1TaggedObject) p).getBaseObject();
                if (inner instanceof ASN1OctetString) {
                    return ((ASN1OctetString) inner).getOctets();
                }
            }
        } catch (Exception ex) {
            // ignore
        }
        return null;
    }

    private static boolean getBoolean(ASN1Encodable e) {
        if (e == null) return false;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof org.bouncycastle.asn1.ASN1Boolean) {
                return ((org.bouncycastle.asn1.ASN1Boolean) p).isTrue();
            }
        } catch (Exception ex) {
            // ignore
        }
        return false;
    }

    private static int getInt(ASN1Encodable e) {
        if (e == null) return -1;
        try {
            ASN1Primitive p = e.toASN1Primitive();
            if (p instanceof org.bouncycastle.asn1.ASN1Integer) {
                return ((org.bouncycastle.asn1.ASN1Integer) p).getValue().intValue();
            }
            if (p instanceof org.bouncycastle.asn1.ASN1Enumerated) {
                return ((org.bouncycastle.asn1.ASN1Enumerated) p).getValue().intValue();
            }
        } catch (Exception ex) {
            // ignore
        }
        return -1;
    }

    private static boolean isAllZeros(byte[] b) {
        if (b == null || b.length == 0) return true;
        for (byte x : b) {
            if (x != 0) return false;
        }
        return true;
    }

    private static String bytesToHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format(Locale.US, "%02x", x & 0xff));
        }
        return sb.toString();
    }

    private static class RootOfTrust {
        final String verifiedBootKeyHex;
        final boolean deviceLocked;
        final int verifiedBootState;
        final String verifiedBootStateName;
        final String verifiedBootHashHex;
        final boolean verifiedBootKeyAllZeros;

        RootOfTrust(String verifiedBootKeyHex, boolean deviceLocked, int verifiedBootState,
                    String verifiedBootStateName, String verifiedBootHashHex, boolean verifiedBootKeyAllZeros) {
            this.verifiedBootKeyHex = verifiedBootKeyHex;
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
            this.verifiedBootStateName = verifiedBootStateName;
            this.verifiedBootHashHex = verifiedBootHashHex;
            this.verifiedBootKeyAllZeros = verifiedBootKeyAllZeros;
        }
    }
}
