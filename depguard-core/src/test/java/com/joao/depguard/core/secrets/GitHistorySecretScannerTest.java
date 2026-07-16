package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.testsupport.FakeSecrets;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.revwalk.RevCommit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Usa repositórios git DE VERDADE (criados via JGit num @TempDir), não mocks —
 * o ponto do modo GIT_HISTORY é o comportamento real do git com histórico.
 */
class GitHistorySecretScannerTest {

    private final GitHistorySecretScanner scanner = new GitHistorySecretScanner();
    private final WorkingTreeSecretScanner workingTreeScanner = new WorkingTreeSecretScanner();

    /**
     * A razão de existir do modo: o working tree está limpo, mas o segredo
     * continua no histórico — quem clonar o repo ainda consegue lê-lo.
     */
    @Test
    void segredoDeletadoContinuaNoHistoricoMesmoComWorkingTreeLimpo(@TempDir Path repo) throws Exception {
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            write(repo, "config.env", "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            commit(git, "adiciona segredo");

            Files.delete(repo.resolve("config.env"));
            git.rm().addFilepattern("config.env").call();
            commit(git, "remove segredo");
        }

        // working tree limpo: nada a achar
        assertThat(workingTreeScanner.scan(repo, Allowlist.empty())).isEmpty();

        // histórico: o segredo continua lá
        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty());
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("DG-SECRET-AWS-ACCESS-KEY");
        assertThat(findings.get(0).path()).isEqualTo("config.env");
    }

    @Test
    void atribuiOCommitQueIntroduziuOSegredo(@TempDir Path repo) throws Exception {
        String introducedIn;
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            write(repo, "readme.md", "sem segredo aqui\n");
            commit(git, "commit inicial limpo");

            write(repo, "config.env", "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            introducedIn = commit(git, "adiciona segredo").getName();

            write(repo, "outro.txt", "mudanca sem relacao\n");
            commit(git, "commit posterior");
        }

        List<SecretFinding> findings = scanner.scan(repo, Allowlist.empty());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).commitSha()).isEqualTo(introducedIn);
    }

    /**
     * Commits posteriores apenas CARREGAM o segredo (não o adicionam), então
     * não podem reacusá-lo — só linhas adicionadas contam.
     */
    @Test
    void naoReportaOMesmoSegredoUmaVezPorCommitPosterior(@TempDir Path repo) throws Exception {
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            write(repo, "config.env", "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            commit(git, "adiciona segredo");

            for (int i = 0; i < 3; i++) {
                write(repo, "arquivo" + i + ".txt", "conteudo " + i + "\n");
                commit(git, "commit posterior " + i);
            }
        }

        assertThat(scanner.scan(repo, Allowlist.empty())).hasSize(1);
    }

    @Test
    void deduplicaSegredoIntroduzidoRemovidoEReintroduzido(@TempDir Path repo) throws Exception {
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            write(repo, "config.env", "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            commit(git, "adiciona");

            Files.delete(repo.resolve("config.env"));
            git.rm().addFilepattern("config.env").call();
            commit(git, "remove");

            write(repo, "config.env", "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            commit(git, "reintroduz");
        }

        // mesmo ruleId+path+hash => mesmo fingerprint => 1 finding, não 2
        assertThat(scanner.scan(repo, Allowlist.empty())).hasSize(1);
    }

    @Test
    void allowlistPorFingerprintSuprimeAchadoIgualAosOutrosModos(@TempDir Path repo) throws Exception {
        try (Git git = Git.init().setDirectory(repo.toFile()).call()) {
            write(repo, "config.env", "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            commit(git, "adiciona segredo");
        }

        String fingerprint = scanner.scan(repo, Allowlist.empty()).get(0).fingerprint();

        Allowlist allowlist = new Allowlist(Set.of(), Set.of(), Set.of(fingerprint));
        assertThat(scanner.scan(repo, allowlist)).isEmpty();
    }

    @Test
    void repositorioSemCommitsNaoQuebra(@TempDir Path repo) throws Exception {
        try (Git ignored = Git.init().setDirectory(repo.toFile()).call()) {
            // nenhum commit
        }

        assertThat(scanner.scan(repo, Allowlist.empty())).isEmpty();
    }

    private void write(Path repo, String relativePath, String content) throws IOException {
        Path file = repo.resolve(relativePath);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }

    private RevCommit commit(Git git, String message) throws Exception {
        git.add().addFilepattern(".").call();
        return git.commit()
                .setMessage(message)
                .setAuthor("Teste", "teste@example.com")
                .setSign(false) // não depende da config de assinatura da máquina
                .call();
    }
}
