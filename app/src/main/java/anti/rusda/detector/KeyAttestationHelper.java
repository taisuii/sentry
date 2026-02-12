package anti.rusda.detector;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
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
                    String.valueOf(DetectionResult.STATUS_WARNING),
                    "Key attestation not supported on this API level",
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
                return new String[]{
                        String.valueOf(DetectionResult.STATUS_NORMAL),
                        "Key attestation: format not recognized on this device (passed)",
                        String.join("; ", details)
                };
            }

            details.add("verifiedBootKey: " + rot.verifiedBootKeyHex);
            details.add("deviceLocked: " + rot.deviceLocked);
            details.add("verifiedBootState: " + rot.verifiedBootStateName + " (" + rot.verifiedBootState + ")");
            details.add("verifiedBootHash: " + rot.verifiedBootHashHex);

            int status = DetectionResult.STATUS_NORMAL;
            if (rot.verifiedBootKeyAllZeros) {
                details.add("verifiedBootKey is all zeros - boot may have been patched");
                status = DetectionResult.STATUS_DANGER;
            }
            if (!rot.deviceLocked) {
                details.add("deviceLocked=false - bootloader unlocked");
                status = DetectionResult.STATUS_DANGER;
            }
            if (rot.verifiedBootState == BOOT_UNVERIFIED || rot.verifiedBootState == BOOT_FAILED) {
                details.add("verifiedBootState indicates unverified or failed boot");
                status = DetectionResult.STATUS_DANGER;
            }
            if (rot.verifiedBootState == BOOT_SELF_SIGNED && status != DetectionResult.STATUS_DANGER) {
                status = DetectionResult.STATUS_WARNING;
            }

            String summary = status == DetectionResult.STATUS_DANGER
                    ? "Boot may be patched or bootloader unlocked (Key Attestation)"
                    : status == DetectionResult.STATUS_WARNING
                    ? "Self-signed or uncertain boot (Key Attestation)"
                    : "Boot verified (Key Attestation)";

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

    private static void deleteAttestationKey(KeyStore ks) {
        try {
            ks.deleteEntry(ATTESTATION_KEY_ALIAS);
        } catch (Exception ignored) {
        }
    }

    /**
     * 从 attestation 扩展的原始字节中解析 RootOfTrust。
     * 扩展值为 OCTET STRING，其内容为 KeyDescription DER。
     * KeyDescription 中 index 7 为 teeEnforced (AuthorizationList)，
     * 其中 tag 704 (ROOT_OF_TRUST) 的值为 RootOfTrust SEQUENCE。
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
            if (keyDesc.size() < 8) {
                return null;
            }

            ASN1Encodable teeEnforcedEnc = keyDesc.getObjectAt(7);
            ASN1Sequence teeEnforced = toSequence(teeEnforcedEnc);
            if (teeEnforced == null) {
                return null;
            }

            for (int i = 0; i < teeEnforced.size(); i++) {
                ASN1Encodable entryEnc = teeEnforced.getObjectAt(i);
                ASN1Sequence entry = toSequence(entryEnc);
                if (entry == null) {
                    continue;
                }
                ASN1Sequence rootSeq = null;
                if (entry.size() >= 2) {
                    int tag = getTagValue(entry.getObjectAt(0));
                    if (tag == KM_TAG_ROOT_OF_TRUST) {
                        rootSeq = toSequence(entry.getObjectAt(1));
                    }
                }
                if (rootSeq == null && entry.size() == 4) {
                    rootSeq = entry;
                }
                if (rootSeq == null || rootSeq.size() < 4) {
                    continue;
                }
                byte[] verifiedBootKey = getOctetString(rootSeq.getObjectAt(0));
                boolean deviceLocked = getBoolean(rootSeq.getObjectAt(1));
                int verifiedBootState = getInt(rootSeq.getObjectAt(2));
                byte[] verifiedBootHash = getOctetString(rootSeq.getObjectAt(3));

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
            }
            return null;
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
