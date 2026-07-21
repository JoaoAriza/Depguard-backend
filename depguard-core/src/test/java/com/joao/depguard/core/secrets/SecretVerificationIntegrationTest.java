package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.VerificationStatus;
import com.joao.depguard.core.secrets.verify.SecretVerification;
import com.joao.depguard.core.secrets.verify.SecretVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica a integração do scanner de working tree com a verificação, sem
 * tocar a rede (verificador fake).
 */
class SecretVerificationIntegrationTest {

    private final WorkingTreeSecretScanner scanner = new WorkingTreeSecretScanner();

    @Test
    void semVerificacaoTudoFicaNotChecked(@TempDir Path repo) throws IOException {
        writeGithubToken(repo);

        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).verificationStatus()).isEqualTo(VerificationStatus.NOT_CHECKED);
    }

    @Test
    void comVerificacaoOStatusVemDoVerificador(@TempDir Path repo) throws IOException {
        writeGithubToken(repo);
        SecretVerification verification = SecretVerification.of(List.of(alwaysVerified()));

        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty(), verification);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).verificationStatus()).isEqualTo(VerificationStatus.VERIFIED);
        // o miolo do token nunca aparece no finding (a amostra mascarada mostra
        // só prefixo + últimos 4 de propósito, mas o valor cru some)
        assertThat(findings.get(0).toString()).doesNotContain("abcdefghijklmnop");
    }

    private void writeGithubToken(Path repo) throws IOException {
        // token com FORMATO válido (gh + p + _ + 36 alfanuméricos), mas fake
        String token = "gh" + "p" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789AB";
        Files.writeString(repo.resolve("app.env"), "GITHUB_TOKEN=" + token + "\n");
    }

    private SecretVerifier alwaysVerified() {
        return new SecretVerifier() {
            @Override public boolean supports(String ruleId) {
                return "DG-SECRET-GITHUB-TOKEN".equals(ruleId);
            }
            @Override public VerificationStatus verify(String rawValue) {
                return VerificationStatus.VERIFIED;
            }
        };
    }
}
