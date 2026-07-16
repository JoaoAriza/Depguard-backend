package com.joao.depguard.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.deps.osv.OsvApi;
import com.joao.depguard.core.deps.osv.OsvPackageQuery;
import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.ScanRequest;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretScanMode;
import com.joao.depguard.core.testsupport.FakeSecrets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultScannerTest {

    private JsonNode osvFixture() throws Exception {
        try (InputStream in = getClass().getResourceAsStream(
                "/osv/lodash-CVE-2021-23337.json")) {
            return new ObjectMapper().readTree(in);
        }
    }

    private OsvApi fakeOsvApi(JsonNode lodashVuln) {
        return new OsvApi() {
            @Override
            public List<List<String>> queryBatch(List<OsvPackageQuery> queries) {
                return queries.stream()
                        .map(q -> "lodash".equals(q.name())
                                ? List.of("GHSA-35jh-r3h4-6jhm")
                                : List.<String>of())
                        .toList();
            }

            @Override
            public JsonNode getVuln(String id) {
                return lodashVuln;
            }
        };
    }

    @Test
    void escaneiaDepsESegredosJuntos(@TempDir Path repo) throws Exception {
        Files.writeString(repo.resolve("package-lock.json"), """
                {
                  "name": "demo", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
                  "packages": {
                    "": { "dependencies": { "lodash": "^4.17.20" } },
                    "node_modules/lodash": { "version": "4.17.20", "license": "MIT" }
                  }
                }
                """);
        Path configDir = repo.resolve("config");
        Files.createDirectories(configDir);
        Files.writeString(configDir.resolve("app.env"), "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");

        DefaultScanner scanner = new DefaultScanner(fakeOsvApi(osvFixture()));
        ScanRequest request = new ScanRequest(
                repo, Set.of(Engine.DEPENDENCIES, Engine.SECRETS),
                SecretScanMode.WORKING_TREE, Allowlist.empty(), false);

        ScanResult result = scanner.scan(request);

        assertThat(result.components()).hasSize(1);
        assertThat(result.vulnFindings()).hasSize(1);
        assertThat(result.vulnFindings().get(0).osvId()).isEqualTo("GHSA-35jh-r3h4-6jhm");
        assertThat(result.secretFindings()).hasSize(1);
        assertThat(result.secretFindings().get(0).ruleId()).isEqualTo("DG-SECRET-AWS-ACCESS-KEY");
        assertThat(result.meta().partial()).isFalse();
        assertThat(result.meta().ecosystems()).containsExactly("npm");
    }

    @Test
    void marcaResultadoParcialQuandoNaoHaLockfile(@TempDir Path repo) throws IOException {
        DefaultScanner scanner = new DefaultScanner(fakeOsvApi(null));
        ScanRequest request = new ScanRequest(
                repo, Set.of(Engine.DEPENDENCIES),
                SecretScanMode.WORKING_TREE, Allowlist.empty(), false);

        ScanResult result = scanner.scan(request);

        assertThat(result.components()).isEmpty();
        assertThat(result.meta().partial()).isTrue();
    }

    @Test
    void combinaComponentesDeNpmEPypiNoMesmoScan(@TempDir Path repo) throws IOException {
        Files.writeString(repo.resolve("package-lock.json"), """
                {
                  "name": "demo", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
                  "packages": {
                    "": { "dependencies": { "lodash": "^4.17.20" } },
                    "node_modules/lodash": { "version": "4.17.20" }
                  }
                }
                """);
        Files.writeString(repo.resolve("requirements.txt"), "flask==2.0.1\n");

        DefaultScanner scanner = new DefaultScanner(fakeOsvApi(null));
        ScanRequest request = new ScanRequest(
                repo, Set.of(Engine.DEPENDENCIES),
                SecretScanMode.WORKING_TREE, Allowlist.empty(), false);

        ScanResult result = scanner.scan(request);

        assertThat(result.components()).hasSize(2);
        assertThat(result.meta().ecosystems()).containsExactlyInAnyOrder("npm", "pypi");
        // npm tem lockfile completo, mas requirements.txt é sempre parcial —
        // o resultado combinado herda o "pior caso" das duas engines.
        assertThat(result.meta().partial()).isTrue();
    }

    @Test
    void poetryLockGeraComponentesCompletosMesmoQuePartialVenhaDoNpmAusente(@TempDir Path repo)
            throws IOException {
        Files.writeString(repo.resolve("poetry.lock"), """
                [[package]]
                name = "flask"
                version = "2.0.1"
                optional = false
                python-versions = ">=3.7"

                [metadata]
                lock-version = "2.0"
                python-versions = "^3.9"
                content-hash = "x"
                """);

        DefaultScanner scanner = new DefaultScanner(fakeOsvApi(null));
        ScanRequest request = new ScanRequest(
                repo, Set.of(Engine.DEPENDENCIES),
                SecretScanMode.WORKING_TREE, Allowlist.empty(), false);

        ScanResult result = scanner.scan(request);

        assertThat(result.components()).hasSize(1);
        assertThat(result.meta().ecosystems()).containsExactly("pypi");
        // poetry.lock (like package-lock.json) é o caminho feliz com dados completos;
        // só o npm (ausente aqui) contribui partial=true nesse cenário.
        assertThat(result.meta().partial()).isTrue();
    }

    @Test
    void engineDesligadaNaoRodaNemDaErro(@TempDir Path repo) throws IOException {
        Files.writeString(repo.resolve("config.txt"), "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");

        DefaultScanner scanner = new DefaultScanner(fakeOsvApi(null));
        ScanRequest request = new ScanRequest(
                repo, Set.of(Engine.DEPENDENCIES), // SECRETS não habilitada
                SecretScanMode.WORKING_TREE, Allowlist.empty(), false);

        ScanResult result = scanner.scan(request);

        assertThat(result.secretFindings()).isEmpty();
    }

    /**
     * Roteamento do modo GIT_HISTORY (antes este teste afirmava que o modo
     * lançava "não implementado" — agora ele é implementado, então o que
     * importa é que o DefaultScanner encaminhe pro scanner de histórico).
     */
    @Test
    void modoGitHistoryVarreOHistoricoDoRepositorio(@TempDir Path repo) throws Exception {
        try (org.eclipse.jgit.api.Git git =
                     org.eclipse.jgit.api.Git.init().setDirectory(repo.toFile()).call()) {
            Files.writeString(repo.resolve("config.env"), "AWS_KEY=" + FakeSecrets.AWS_ACCESS_KEY + "\n");
            git.add().addFilepattern(".").call();
            git.commit().setMessage("adiciona segredo")
                    .setAuthor("Teste", "teste@example.com").setSign(false).call();
            // apaga do working tree: só o histórico ainda tem o segredo
            Files.delete(repo.resolve("config.env"));
            git.rm().addFilepattern("config.env").call();
            git.commit().setMessage("remove segredo")
                    .setAuthor("Teste", "teste@example.com").setSign(false).call();
        }

        DefaultScanner scanner = new DefaultScanner(fakeOsvApi(null));
        ScanRequest request = new ScanRequest(
                repo, Set.of(Engine.SECRETS),
                SecretScanMode.GIT_HISTORY, Allowlist.empty(), false);

        ScanResult result = scanner.scan(request);

        assertThat(result.secretFindings()).hasSize(1);
        assertThat(result.secretFindings().get(0).commitSha()).isNotBlank();
    }
}
