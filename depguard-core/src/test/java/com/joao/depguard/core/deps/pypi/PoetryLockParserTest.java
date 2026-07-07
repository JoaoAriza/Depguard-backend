package com.joao.depguard.core.deps.pypi;

import com.joao.depguard.core.model.Component;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class PoetryLockParserTest {

    private final PoetryLockParser parser = new PoetryLockParser();

    @Test
    void parseiaPoetryLockENormalizaNomePep503() throws Exception {
        Path lock = Path.of(getClass().getResource("/pypi/poetry.lock").toURI());
        List<Component> components = parser.parse(lock);

        assertThat(components).hasSize(2);
        Map<String, Component> byName = components.stream()
                .collect(Collectors.toMap(Component::name, Function.identity()));

        // "Requests" (maiúsculo no arquivo) normalizado pra "requests" (PEP 503)
        Component requests = byName.get("requests");
        assertThat(requests).isNotNull();
        assertThat(requests.ecosystem()).isEqualTo("pypi");
        assertThat(requests.version()).isEqualTo("2.31.0");
        assertThat(requests.purl()).isEqualTo("pkg:pypi/requests@2.31.0");
        assertThat(requests.direct()).isTrue();
        assertThat(requests.depth()).isZero();

        assertThat(byName.get("certifi").version()).isEqualTo("2024.2.2");
    }
}
