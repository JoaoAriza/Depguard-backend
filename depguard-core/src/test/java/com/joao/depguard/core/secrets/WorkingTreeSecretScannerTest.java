package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.VerificationStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class WorkingTreeSecretScannerTest {

    private final WorkingTreeSecretScanner scanner = new WorkingTreeSecretScanner();

    @Test
    void detectaChaveAwsEMascaraOValor(@TempDir Path repo) throws IOException {
        write(repo, "config/app.env", "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n");

        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty());

        assertThat(findings).hasSize(1);
        SecretFinding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("DG-SECRET-AWS-ACCESS-KEY");
        assertThat(f.path()).isEqualTo("config/app.env");
        assertThat(f.lineStart()).isEqualTo(1);
        assertThat(f.maskedSample()).isEqualTo("AKIA…MNOP");
        assertThat(f.secretHash()).isNotBlank();
        assertThat(f.verificationStatus()).isEqualTo(VerificationStatus.NOT_CHECKED);
        assertThat(f.allowlisted()).isFalse();
        // nunca guarda o valor cru em nenhum campo texto
        assertThat(f.toString()).doesNotContain("AKIAABCDEFGHIJKLMNOP");
    }

    @Test
    void ignoraPlaceholderObvio(@TempDir Path repo) throws IOException {
        write(repo, ".env.example", "AWS_KEY=AKIAXXXXXXXXXXXXXXXX\n");

        assertThat(scanner.scan(repo, Allowlist.empty())).isEmpty();
    }

    @Test
    void allowlistPorPathSuprimeAchado(@TempDir Path repo) throws IOException {
        write(repo, "src/test/fixtures/creds.txt", "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n");

        Allowlist allowlist = new Allowlist(Set.of("**/fixtures/**"), Set.of(), Set.of());
        assertThat(scanner.scan(repo, allowlist)).isEmpty();
    }

    @Test
    void allowlistPorRegexDeValorSuprimeAchado(@TempDir Path repo) throws IOException {
        write(repo, "config/app.env", "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n");

        Allowlist allowlist = new Allowlist(Set.of(), Set.of("^AKIAABCDEFGHIJKLMNOP$"), Set.of());
        assertThat(scanner.scan(repo, allowlist)).isEmpty();
    }

    @Test
    void allowlistPorFingerprintSuprimeAchado(@TempDir Path repo) throws IOException {
        write(repo, "config/app.env", "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n");

        List<SecretFinding> first = scanner.scan(repo, Allowlist.empty());
        String fingerprint = first.get(0).fingerprint();

        Allowlist allowlist = new Allowlist(Set.of(), Set.of(), Set.of(fingerprint));
        assertThat(scanner.scan(repo, allowlist)).isEmpty();
    }

    @Test
    void naoEscaneiaDentroDeNodeModulesENoDotGit(@TempDir Path repo) throws IOException {
        write(repo, "node_modules/pkg/index.js", "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n");
        write(repo, ".git/config", "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n");

        assertThat(scanner.scan(repo, Allowlist.empty())).isEmpty();
    }

    @Test
    void detectaSegredoGenericoPorEntropiaComChaveDeAtribuicao(@TempDir Path repo) throws IOException {
        write(repo, "config/secrets.yaml", "token: \"aK9mZ2pL0xQvR3nB7cD1eF4gH6\"\n");

        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("DG-SECRET-GENERIC-HIGH-ENTROPY");
    }

    @Test
    void jwtEhDetectadoPelaRegraEspecifica(@TempDir Path repo) throws IOException {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzYWZha2VzaWduYXR1cmU";
        write(repo, "src/app.js", "const t = \"" + jwt + "\";\n");

        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty());

        assertThat(findings).anyMatch(f -> f.ruleId().equals("DG-SECRET-JWT"));
    }

    private void write(Path repo, String relativePath, String content) throws IOException {
        Path file = repo.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
