package com.joao.depguard.core.deps.maven;

import com.joao.depguard.core.model.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Parseia a saída de {@code mvn dependency:tree -DoutputType=text}
 * (docs/architecture.md §2.1). Formato confirmado contra a saída real do
 * Maven 3.9, não assumido de memória:
 *
 * <pre>
 * com.joao:projeto:jar:1.0.0                         &lt;- raiz (o próprio projeto, ignorada)
 * +- group:artifact:jar:2.15.4:compile               &lt;- direta (depth 0)
 * |  +- group:outra:jar:1.0:compile                  &lt;- transitiva (depth 1)
 * |  \- group:mais:jar:1.0:compile
 * \- group:ultima:jar:3.0:test
 * </pre>
 *
 * <p>Coordenadas: {@code groupId:artifactId:type[:classifier]:version:scope}.
 * O version é o penúltimo campo e o scope o último — parsear a partir do fim
 * lida com o classifier opcional sem casos especiais.
 *
 * <p>Inclui TODOS os escopos (compile/runtime/test/provided), consistente com
 * o parser npm que inclui devDependencies — uma vuln em dep de teste também
 * importa (ataque de supply-chain roda no CI).
 */
public class MavenDependencyTreeParser {

    public List<Component> parse(String treeOutput) {
        List<Component> components = new ArrayList<>();
        if (treeOutput == null || treeOutput.isBlank()) {
            return components;
        }

        for (String line : treeOutput.split("\r?\n")) {
            int marker = markerIndex(line);
            if (marker < 0) {
                continue; // raiz (sem prefixo de árvore) ou linha não-dependência
            }
            int depth = marker / 3; // cada nível de indentação são 3 chars ("|  " ou "   ")
            Component c = toComponent(line.substring(marker + 3).trim(), depth);
            if (c != null) {
                components.add(c);
            }
        }
        return components;
    }

    /** Índice do "+- " ou "\- " que marca o início das coordenadas; -1 se não houver. */
    private int markerIndex(String line) {
        int plus = line.indexOf("+- ");
        int slash = line.indexOf("\\- ");
        if (plus < 0) {
            return slash;
        }
        if (slash < 0) {
            return plus;
        }
        return Math.min(plus, slash);
    }

    private Component toComponent(String coords, int depth) {
        String[] parts = coords.split(":");
        if (parts.length < 5) {
            return null; // formato inesperado: ignora em vez de quebrar o scan
        }
        String groupId = parts[0];
        String artifactId = parts[1];
        String version = parts[parts.length - 2];
        String name = groupId + ":" + artifactId;
        String purl = "pkg:maven/" + groupId + "/" + artifactId + "@" + version;

        return new Component("maven", name, version, purl, depth == 0, depth, List.of());
    }
}
