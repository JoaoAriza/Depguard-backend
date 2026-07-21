package com.joao.depguard.core.deps.maven;

import com.joao.depguard.core.model.Component;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * As fixtures abaixo são a saída REAL de {@code mvn dependency:tree
 * -DoutputType=text} do Maven 3.9 (capturada do próprio reator do DepGuard),
 * não inventada.
 */
class MavenDependencyTreeParserTest {

    private final MavenDependencyTreeParser parser = new MavenDependencyTreeParser();

    @Test
    void ignoraARaizEMarcaDiretasComoDepth0() {
        String tree = """
                com.joao.depguard:depguard-core:jar:0.0.1-SNAPSHOT
                +- com.fasterxml.jackson.core:jackson-databind:jar:2.15.4:compile
                |  +- com.fasterxml.jackson.core:jackson-annotations:jar:2.15.4:compile
                |  \\- com.fasterxml.jackson.core:jackson-core:jar:2.15.4:compile
                \\- org.assertj:assertj-core:jar:3.24.2:test
                """;

        List<Component> components = parser.parse(tree);

        // a raiz (o próprio projeto) NÃO vira componente
        assertThat(components).extracting(Component::name)
                .doesNotContain("com.joao.depguard:depguard-core");

        Component databind = byName(components, "com.fasterxml.jackson.core:jackson-databind");
        assertThat(databind.direct()).isTrue();
        assertThat(databind.depth()).isZero();
        assertThat(databind.version()).isEqualTo("2.15.4");
        assertThat(databind.ecosystem()).isEqualTo("maven");
        assertThat(databind.purl()).isEqualTo("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.4");
    }

    @Test
    void transitivasRecebemDepthCrescenteENaoSaoDiretas() {
        String tree = """
                root:proj:jar:1.0
                +- a:direta:jar:1.0:compile
                |  \\- b:trans1:jar:1.0:compile
                |     \\- c:trans2:jar:1.0:compile
                """;

        List<Component> components = parser.parse(tree);

        assertThat(byName(components, "a:direta").depth()).isZero();
        assertThat(byName(components, "b:trans1").depth()).isEqualTo(1);
        assertThat(byName(components, "c:trans2").depth()).isEqualTo(2);
        assertThat(byName(components, "b:trans1").direct()).isFalse();
    }

    @Test
    void incluiTodosOsEscopos() {
        String tree = """
                root:proj:jar:1.0
                +- a:compileDep:jar:1.0:compile
                +- b:runtimeDep:jar:1.0:runtime
                +- c:testDep:jar:1.0:test
                \\- d:providedDep:jar:1.0:provided
                """;

        assertThat(parser.parse(tree)).hasSize(4);
    }

    /** Artefato com classifier tem 6 campos; version continua sendo o penúltimo. */
    @Test
    void lidaComClassifier() {
        String tree = """
                root:proj:jar:1.0
                +- org.example:foo:jar:tests:2.0:test
                """;

        Component c = byName(parser.parse(tree), "org.example:foo");
        assertThat(c.version()).isEqualTo("2.0");
        assertThat(c.purl()).isEqualTo("pkg:maven/org.example/foo@2.0");
    }

    @Test
    void saidaVaziaOuNulaNaoQuebra() {
        assertThat(parser.parse(null)).isEmpty();
        assertThat(parser.parse("")).isEmpty();
        assertThat(parser.parse("   ")).isEmpty();
    }

    private Component byName(List<Component> components, String name) {
        return components.stream()
                .filter(c -> c.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("componente não encontrado: " + name));
    }
}
