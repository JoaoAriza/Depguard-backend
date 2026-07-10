package com.joao.depguard.server.github;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GithubWebhookSignatureVerifierTest {

    private final GithubWebhookSignatureVerifier verifier = new GithubWebhookSignatureVerifier();

    /** HMAC-SHA256 real, calculado via `openssl dgst -sha256 -hmac` — oráculo independente. */
    private static final String PAYLOAD = "{\"zen\":\"test payload\"}";
    private static final String SECRET = "my-webhook-secret";
    private static final String VALID_SIGNATURE =
            "sha256=b516446d9807c3bebb4e8204602cf61298c7514241f4c5a447e9881b56522268";

    @Test
    void aceitaAssinaturaValidaCalculadaPorFerramentaIndependente() {
        assertThat(verifier.isValid(PAYLOAD, SECRET, VALID_SIGNATURE)).isTrue();
    }

    @Test
    void rejeitaAssinaturaComSecretErrado() {
        assertThat(verifier.isValid(PAYLOAD, "secret-errado", VALID_SIGNATURE)).isFalse();
    }

    @Test
    void rejeitaAssinaturaComPayloadAdulterado() {
        assertThat(verifier.isValid("{\"zen\":\"payload adulterado\"}", SECRET, VALID_SIGNATURE)).isFalse();
    }

    @Test
    void rejeitaHeaderAusente() {
        assertThat(verifier.isValid(PAYLOAD, SECRET, null)).isFalse();
    }

    @Test
    void rejeitaHeaderSemPrefixoSha256() {
        assertThat(verifier.isValid(PAYLOAD, SECRET, "md5=deadbeef")).isFalse();
    }
}
