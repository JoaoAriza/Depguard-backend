package com.joao.depguard.core.deps.maven;

import com.joao.depguard.core.model.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Resolve dependências Maven rodando {@code mvn dependency:tree} no projeto
 * (docs/architecture.md §2.1) — {@code pom.xml} não tem lockfile, então a
 * árvore transitiva só existe resolvendo de verdade.
 *
 * <p><b>ATENÇÃO — risco de RCE:</b> rodar {@code mvn} executa o build do
 * projeto; um {@code pom.xml} ou {@code .mvn/extensions.xml} malicioso roda
 * código arbitrário na máquina. Por isso a resolução é OPT-IN e só deve rodar
 * em código CONFIÁVEL (o próprio repo do dev via CLI). NUNCA rode em checkout
 * não-confiável (ex.: head de PR) — quem chama garante essa fronteira.
 *
 * <p>Degrada com elegância: {@code mvn} ausente, build quebrado ou timeout
 * devolvem lista vazia (o scan segue e marca {@code partial}) em vez de
 * derrubar tudo.
 */
public class MavenResolver {

    private static final long TIMEOUT_MINUTES = 5;

    private final MavenDependencyTreeParser parser = new MavenDependencyTreeParser();

    /** @return componentes resolvidos, ou vazio se não há pom.xml, mvn falta, ou o build falha. */
    public List<Component> resolve(Path repoRoot) {
        if (!Files.isRegularFile(repoRoot.resolve("pom.xml"))) {
            return List.of();
        }

        Path outputFile = null;
        try {
            outputFile = Files.createTempFile("depguard-mvn-tree", ".txt");
            // Argumentos como array (nunca string de shell): sem injeção. O repo
            // é o working dir, não é concatenado em comando.
            Process process = new ProcessBuilder(
                    mavenExecutable(), "-q", "--batch-mode",
                    "dependency:tree", "-DoutputType=text",
                    "-DoutputFile=" + outputFile.toAbsolutePath())
                    .directory(repoRoot.toFile())
                    .redirectErrorStream(true)
                    .start();

            if (!process.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES)) {
                process.destroyForcibly();
                return List.of(); // travou (download infinito?): parcial, não trava o scan
            }
            if (process.exitValue() != 0) {
                return List.of(); // build falhou (projeto não compila, offline sem cache, etc.)
            }

            return parser.parse(Files.readString(outputFile));
        } catch (IOException e) {
            // mvn não encontrado no PATH cai aqui: parcial, não é erro fatal.
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return List.of();
        } finally {
            if (outputFile != null) {
                try {
                    Files.deleteIfExists(outputFile);
                } catch (IOException ignored) {
                    // arquivo temporário órfão: não vale derrubar o scan por isso
                }
            }
        }
    }

    /** No Windows o launcher é {@code mvn.cmd}; o ProcessBuilder não resolve PATHEXT sozinho. */
    private String mavenExecutable() {
        boolean windows = System.getProperty("os.name", "").toLowerCase().contains("win");
        return windows ? "mvn.cmd" : "mvn";
    }
}
