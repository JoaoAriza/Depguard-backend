package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.ChangedFile;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.testsupport.FakeSecrets;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class PrDiffSecretScannerTest {

    private final PrDiffSecretScanner scanner = new PrDiffSecretScanner();

    @Test
    void detectaSegredoEmLinhaAdicionada() {
        String patch = "@@ -0,0 +1,1 @@\n+AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY;
        ChangedFile file = new ChangedFile("config/app.env", patch);

        List<SecretFinding> findings = scanner.scan(List.of(file), Allowlist.empty());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("DG-SECRET-AWS-ACCESS-KEY");
        assertThat(findings.get(0).path()).isEqualTo("config/app.env");
        assertThat(findings.get(0).lineStart()).isEqualTo(1);
    }

    @Test
    void naoReacusaSegredoQueSoApareceComoContextoOuRemovido() {
        // segredo já existia antes do PR (linha de contexto) e outro foi removido —
        // nenhum dos dois deve ser reportado, só o que o PR de fato introduz
        String patch = "@@ -1,2 +1,3 @@\n"
                + " AWS_KEY_OLD=" + FakeSecrets.AWS_ACCESS_KEY + "\n"
                + "-AWS_KEY_REMOVED=" + FakeSecrets.AWS_ACCESS_KEY + "\n"
                + "+SAFE_LINE=hello";
        ChangedFile file = new ChangedFile("config/app.env", patch);

        List<SecretFinding> findings = scanner.scan(List.of(file), Allowlist.empty());

        assertThat(findings).isEmpty();
    }

    @Test
    void arquivoSemPatchEhIgnorado() {
        ChangedFile binaryFile = new ChangedFile("assets/logo.png", null);

        assertThat(scanner.scan(List.of(binaryFile), Allowlist.empty())).isEmpty();
    }

    @Test
    void allowlistPorFingerprintSuprimeAchadoIgualAoWorkingTree() {
        String patch = "@@ -0,0 +1,1 @@\n+AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY;
        ChangedFile file = new ChangedFile("config/app.env", patch);

        List<SecretFinding> first = scanner.scan(List.of(file), Allowlist.empty());
        String fingerprint = first.get(0).fingerprint();

        Allowlist allowlist = new Allowlist(Set.of(), Set.of(), Set.of(fingerprint));
        assertThat(scanner.scan(List.of(file), allowlist)).isEmpty();
    }

    @Test
    void variosArquivosNoMesmoDiffSaoTodosVarridos() {
        String patch1 = "@@ -0,0 +1,1 @@\n+AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY;
        String patch2 = "@@ -0,0 +1,1 @@\n+SAFE=hello";

        List<SecretFinding> findings = scanner.scan(
                List.of(new ChangedFile("a.env", patch1), new ChangedFile("b.env", patch2)),
                Allowlist.empty());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).path()).isEqualTo("a.env");
    }
}
