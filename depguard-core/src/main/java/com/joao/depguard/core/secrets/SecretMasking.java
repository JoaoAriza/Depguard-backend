package com.joao.depguard.core.secrets;

/** Máscara de exibição segura — nunca guardamos o segredo cru (docs/architecture.md §0). */
public final class SecretMasking {

    private SecretMasking() {
    }

    /** Preserva os 4 primeiros e os 4 últimos caracteres; o meio vira "…". */
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
