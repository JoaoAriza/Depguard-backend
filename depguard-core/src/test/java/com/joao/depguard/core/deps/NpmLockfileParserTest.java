package com.joao.depguard.core.deps;

import com.joao.depguard.core.model.Component;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class NpmLockfileParserTest {

    private final NpmLockfileParser parser = new NpmLockfileParser();

    private Path fixture(String name) throws Exception {
        return Path.of(getClass().getResource("/lockfiles/" + name).toURI());
    }

    private Map<String, Component> byName(List<Component> components) {
        return components.stream().collect(Collectors.toMap(Component::name, Function.identity()));
    }

    @Test
    void parseiaLockfileV3() throws Exception {
        List<Component> components = parser.parse(fixture("package-lock.v3.json"));
        Map<String, Component> byName = byName(components);

        assertThat(components).hasSize(4);

        Component lodash = byName.get("lodash");
        assertThat(lodash.ecosystem()).isEqualTo("npm");
        assertThat(lodash.version()).isEqualTo("4.17.20");
        assertThat(lodash.purl()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(lodash.direct()).isTrue();
        assertThat(lodash.depth()).isZero();
        assertThat(lodash.licenses()).containsExactly("MIT");

        Component scoped = byName.get("@scope/util");
        assertThat(scoped.purl()).isEqualTo("pkg:npm/%40scope/util@1.2.3");
        assertThat(scoped.direct()).isTrue();
        assertThat(scoped.licenses()).containsExactly("Apache-2.0");

        // dev dependency declarada na raiz também é direta
        assertThat(byName.get("jest").direct()).isTrue();

        // transitiva aninhada: não-direta, profundidade 1
        Component chalk = byName.get("chalk");
        assertThat(chalk.direct()).isFalse();
        assertThat(chalk.depth()).isEqualTo(1);
    }

    @Test
    void parseiaLockfileV1Legado() throws Exception {
        List<Component> components = parser.parse(fixture("package-lock.v1.json"));
        Map<String, Component> byName = byName(components);

        assertThat(components).hasSize(3);
        assertThat(byName.get("lodash").direct()).isTrue();
        assertThat(byName.get("lodash").depth()).isZero();
        assertThat(byName.get("chalk").direct()).isFalse();
        assertThat(byName.get("chalk").depth()).isEqualTo(1);
    }
}
