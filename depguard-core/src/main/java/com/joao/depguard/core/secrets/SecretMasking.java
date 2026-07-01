package com.joao.depguard.core.secrets;

/** Máscara de exibição segura — nunca guardamos o segredo cru (docs/architecture.md §0). */
public final class SecretMasking {

    private SecretMasking() {
    }

    /** Ex.: "AKIAABCDEFGHIJKLMNOP" -> "AKIA…MNOP". */
    public static String mask(String secret) {
        if (secret == null) {
            return null;
        }
        int len = secret.length();
        if (len <= 8) {
            return "*".repeat(len);
        }
        return secret.substring(0, 4) + "…" + secret.substring(len - 4);
    }
}
