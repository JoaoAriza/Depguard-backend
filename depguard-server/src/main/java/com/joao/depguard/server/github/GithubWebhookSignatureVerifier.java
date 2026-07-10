package com.joao.depguard.server.github;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Verifica a assinatura HMAC-SHA256 que o GitHub manda no header
 * {@code X-Hub-Signature-256} pra provar que o payload do webhook veio do
 * GitHub de verdade e não foi adulterado — sem isso, qualquer um que
 * descubra a URL do webhook poderia forjar eventos (ex.: disparar scans,
 * marcar checks como passando).
 */
@Component
public class GithubWebhookSignatureVerifier {

    private static final String ALGORITHM = "HmacSHA256";
    private static final String PREFIX = "sha256=";

    public boolean isValid(String payload, String secret, String signatureHeader) {
        if (signatureHeader == null || !signatureHeader.startsWith(PREFIX)) {
            return false;
        }
        String expectedHex = signatureHeader.substring(PREFIX.length());
        String actualHex = hmacSha256Hex(payload, secret);

        // MessageDigest.isEqual é tempo-constante — evita timing attack numa
        // comparação byte-a-byte ingênua (ex.: String.equals).
        return MessageDigest.isEqual(
                expectedHex.getBytes(StandardCharsets.UTF_8),
                actualHex.getBytes(StandardCharsets.UTF_8));
    }

    private String hmacSha256Hex(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            byte[] digest = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao calcular HMAC-SHA256", e);
        }
    }
}
