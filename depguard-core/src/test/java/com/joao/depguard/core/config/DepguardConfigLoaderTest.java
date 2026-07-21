package com.joao.depguard.core.config;

import com.joao.depguard.core.model.Allowlist;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DepguardConfigLoaderTest {

    private final DepguardConfigLoader loader = new DepguardConfigLoader();

    @Test
    void semArquivoRetornaAllowlistVazia(@TempDir Path repo) {
        assertThat(loader.load(repo)).isEqualTo(Allowlist.empty());
    }

    @Test
    void leTodasAsSecoesDaAllowlist(@TempDir Path repo) throws IOException {
        write(repo, ".depguard.yml", """
                allowlist:
                  paths:
                    - "**/test/fixtures/**"
                  valueRegexes:
                    - "^AKIAEXAMPLE.*"
                  fingerprints:
                    - "abc123"
                """);

        Allowlist a = loader.load(repo);

        assertThat(a.paths()).containsExactly("**/test/fixtures/**");
        assertThat(a.valueRegexes()).containsExactly("^AKIAEXAMPLE.*");
        assertThat(a.fingerprints()).containsExactly("abc123");
    }

    @Test
    void secaoParcialDeixaAsOutrasVazias(@TempDir Path repo) throws IOException {
        write(repo, ".depguard.yml", """
                allowlist:
                  paths:
                    - "docs/**"
                """);

        Allowlist a = loader.load(repo);

        assertThat(a.paths()).containsExactly("docs/**");
        assertThat(a.valueRegexes()).isEmpty();
        assertThat(a.fingerprints()).isEmpty();
    }

    @Test
    void aceitaExtensaoYaml(@TempDir Path repo) throws IOException {
        write(repo, ".depguard.yaml", """
                allowlist:
                  paths: ["a/**"]
                """);

        assertThat(loader.load(repo).paths()).containsExactly("a/**");
    }

    @Test
    void arquivoVazioNaoQuebra(@TempDir Path repo) throws IOException {
        write(repo, ".depguard.yml", "");

        assertThat(loader.load(repo)).isEqualTo(Allowlist.empty());
    }

    /** YAML quebrado FALHA — não é ignorado em silêncio (allowlist quebrada esconderia supressão). */
    @Test
    void yamlMalformadoFalhaExplicito(@TempDir Path repo) throws IOException {
        write(repo, ".depguard.yml", "allowlist:\n  paths:\n    - [isto: nao fecha\n");

        assertThatThrownBy(() -> loader.load(repo))
                .isInstanceOf(DepguardConfigException.class)
                .hasMessageContaining(".depguard.yml");
    }

    /** Campo desconhecido (ex.: typo) FALHA — supressão que não funciona sem o dev saber é pior que erro. */
    @Test
    void campoDesconhecidoFalha(@TempDir Path repo) throws IOException {
        write(repo, ".depguard.yml", """
                allowlist:
                  fingerprint:
                    - "abc"
                """);

        assertThatThrownBy(() -> loader.load(repo))
                .isInstanceOf(DepguardConfigException.class);
    }

    private void write(Path repo, String name, String content) throws IOException {
        Files.writeString(repo.resolve(name), content);
    }
}
