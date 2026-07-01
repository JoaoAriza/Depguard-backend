package com.joao.depguard.cli;

import com.joao.depguard.core.DefaultScanner;
import com.joao.depguard.core.Scanner;
import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.ScanRequest;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretScanMode;
import com.joao.depguard.core.report.CycloneDxWriter;
import com.joao.depguard.core.report.JsonReportWriter;
import com.joao.depguard.core.report.SarifWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

/**
 * Escaneia um repositório local: dependências npm (via OSV) + segredos
 * (working tree). Escreve JSON, SARIF e SBOM CycloneDX (docs/architecture.md
 * §8, marco "demo enxuto").
 */
@Command(name = "scan", description = "Escaneia um repositório local: dependências (npm) + segredos.")
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", description = "Caminho do repositório a escanear.")
    Path repoRoot;

    @Option(names = "--deps", description = "Habilita a engine de dependências (npm).")
    boolean depsFlag;

    @Option(names = "--secrets", description = "Habilita a engine de segredos.")
    boolean secretsFlag;

    @Option(names = "--out", description = "Diretório de saída dos relatórios. Padrão: o próprio repositório.")
    Path outDir;

    @Option(names = "--allow-path", description = "Glob de caminho a ignorar na varredura de segredos (repetível).")
    List<String> allowPaths = new ArrayList<>();

    @Option(names = "--allow-value-regex", description = "Regex de valor a ignorar na varredura de segredos (repetível).")
    List<String> allowValueRegexes = new ArrayList<>();

    @Override
    public Integer call() {
        if (!Files.isDirectory(repoRoot)) {
            System.err.println("Caminho não é um diretório: " + repoRoot);
            return 2;
        }

        Set<Engine> engines = resolveEngines();
        Path out = outDir != null ? outDir : repoRoot;

        try {
            Files.createDirectories(out);

            Allowlist allowlist = new Allowlist(
                    new LinkedHashSet<>(allowPaths), new LinkedHashSet<>(allowValueRegexes), Set.of());
            ScanRequest request = new ScanRequest(
                    repoRoot, engines, SecretScanMode.WORKING_TREE, allowlist, false);

            Scanner scanner = new DefaultScanner();
            ScanResult result = scanner.scan(request);

            Files.writeString(out.resolve("depguard-report.json"), new JsonReportWriter().write(result));
            Files.writeString(out.resolve("depguard-report.sarif"), new SarifWriter().write(result));
            Files.writeString(out.resolve("depguard-sbom.cdx.json"), new CycloneDxWriter().write(result));

            printSummary(result, out);
            return 0;
        } catch (Exception e) {
            System.err.println("Falha no scan: " + e.getMessage());
            return 1;
        }
    }

    private Set<Engine> resolveEngines() {
        Set<Engine> engines = EnumSet.noneOf(Engine.class);
        if (depsFlag) {
            engines.add(Engine.DEPENDENCIES);
        }
        if (secretsFlag) {
            engines.add(Engine.SECRETS);
        }
        if (engines.isEmpty()) {
            engines.add(Engine.DEPENDENCIES);
            engines.add(Engine.SECRETS);
        }
        return engines;
    }

    private void printSummary(ScanResult result, Path out) {
        System.out.println("DepGuard — scan concluído em " + result.meta().durationMillis() + "ms");
        if (result.meta().partial()) {
            System.out.println("  AVISO: resultado parcial (sem lockfile suportado encontrado)");
        }
        System.out.println("  componentes:      " + result.components().size());
        System.out.println("  vulnerabilidades: " + result.vulnFindings().size());
        System.out.println("  segredos:         " + result.secretFindings().size());
        System.out.println("  relatórios escritos em " + out.toAbsolutePath());
    }
}
