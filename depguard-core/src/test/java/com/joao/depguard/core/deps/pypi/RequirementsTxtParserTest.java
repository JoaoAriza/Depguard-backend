package com.joao.depguard.core.deps.pypi;

import com.joao.depguard.core.model.Component;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class RequirementsTxtParserTest {

    private final RequirementsTxtParser parser = new RequirementsTxtParser();

    @Test
    void extraiSoPinsExatosEIgnoraORestante(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("requirements.txt");
        Files.writeString(file, """
                # comentário isolado
                Flask==2.0.1
                requests[security]==2.25.1  # comentário no fim da linha
                Django==3.2.13 ; python_version >= "3.6"

                click
                gunicorn>=20.0.0,<21.0
                -e git+https://github.com/foo/bar.git#egg=bar
                -r other-requirements.txt
                --index-url https://pypi.org/simple
                """);

        List<Component> components = parser.parse(file);

        assertThat(components).hasSize(3);
        Map<String, Component> byName = components.stream()
                .collect(Collectors.toMap(Component::name, Function.identity()));

        assertThat(byName.get("flask").version()).isEqualTo("2.0.1");
        assertThat(byName.get("flask").purl()).isEqualTo("pkg:pypi/flask@2.0.1");
        assertThat(byName.get("flask").direct()).isTrue();

        assertThat(byName.get("requests").version()).isEqualTo("2.25.1");
        assertThat(byName.get("django").version()).isEqualTo("3.2.13");

        // "click" (sem versão) e "gunicorn" (range, sem pin exato) ficam de fora
        assertThat(byName).doesNotContainKeys("click", "gunicorn");
    }

    @Test
    void arquivoSoComRangesNaoGeraComponenteAlgum(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("requirements.txt");
        Files.writeString(file, "requests>=2.25.0\nflask~=2.0\n");

        assertThat(parser.parse(file)).isEmpty();
    }
}
