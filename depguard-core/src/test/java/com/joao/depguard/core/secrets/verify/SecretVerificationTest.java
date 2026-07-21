package com.joao.depguard.core.secrets.verify;

import com.joao.depguard.core.model.VerificationStatus;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Testes herméticos — usam verificadores fake, nunca tocam a rede. A checagem
 * real contra a API do GitHub é verificação manual ao vivo (mesma disciplina
 * do OSV/EPSS), não teste unitário.
 */
class SecretVerificationTest {

    @Test
    void desligadoRetornaNotCheckedSemChamarVerificador() {
        AtomicInteger calls = new AtomicInteger();
        SecretVerification v = SecretVerification.disabled();

        assertThat(v.verify("DG-SECRET-GITHUB-TOKEN", "hash1", "raw"))
                .isEqualTo(VerificationStatus.NOT_CHECKED);
        assertThat(calls.get()).isZero();
    }

    @Test
    void roteiaProVerificadorQueSuportaARegra() {
        SecretVerifier github = fake("DG-SECRET-GITHUB-TOKEN", VerificationStatus.VERIFIED);
        SecretVerification v = SecretVerification.of(List.of(github));

        assertThat(v.verify("DG-SECRET-GITHUB-TOKEN", "h", "raw"))
                .isEqualTo(VerificationStatus.VERIFIED);
    }

    @Test
    void regraSemVerificadorFicaNotChecked() {
        SecretVerifier github = fake("DG-SECRET-GITHUB-TOKEN", VerificationStatus.VERIFIED);
        SecretVerification v = SecretVerification.of(List.of(github));

        // AWS não tem verificador → não dá pra afirmar nada
        assertThat(v.verify("DG-SECRET-AWS-ACCESS-KEY", "h", "raw"))
                .isEqualTo(VerificationStatus.NOT_CHECKED);
    }

    @Test
    void deduplicaPorHashChamandoOVerificadorUmaVezSo() {
        AtomicInteger calls = new AtomicInteger();
        SecretVerifier counting = new SecretVerifier() {
            @Override public boolean supports(String ruleId) { return true; }
            @Override public VerificationStatus verify(String rawValue) {
                calls.incrementAndGet();
                return VerificationStatus.VERIFIED;
            }
        };
        SecretVerification v = SecretVerification.of(List.of(counting));

        v.verify("DG-SECRET-GITHUB-TOKEN", "mesmo-hash", "raw");
        v.verify("DG-SECRET-GITHUB-TOKEN", "mesmo-hash", "raw");
        v.verify("DG-SECRET-GITHUB-TOKEN", "outro-hash", "raw");

        assertThat(calls.get()).isEqualTo(2); // 1 por hash distinto
    }

    private SecretVerifier fake(String ruleId, VerificationStatus status) {
        return new SecretVerifier() {
            @Override public boolean supports(String r) { return ruleId.equals(r); }
            @Override public VerificationStatus verify(String rawValue) { return status; }
        };
    }
}
