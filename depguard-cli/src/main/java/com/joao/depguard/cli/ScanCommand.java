package com.joao.depguard.cli;

import com.joao.depguard.core.DefaultScanner;
import com.joao.depguard.core.Scanner;
import com.joao.depguard.core.config.DepguardConfigLoader;
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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
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

    @Option(names = "--enrich", description = "Enriquece vulnerabilidades com EPSS/KEV (2 chamadas de rede extras).")
    boolean enrichFlag;

    @Option(names = "--history",
            description = "Varre o histórico do git em vez do working tree (acha segredo já deletado). Mais lento.")
    boolean historyFlag;

    @Option(names = "--verify-secrets",
            description = "Checa ao vivo se cada segredo é credencial ATIVA (envia o valor pro provedor legítimo). Opt-in.")
    boolean verifySecretsFlag;

    @Option(names = "--out", description = "Diretório de saída dos relatórios. Padrão: o próprio repositório.")
    Path outDir;

    @Option(names = "--allow-path", description = "Glob de caminho a ignorar na varredura de segredos (repetível).")
    List<String> allowPaths = new ArrayList<>();

    @Option(names = "--allow-value-regex", description = "Regex de valor a ignorar na varredura de segredos (repetível).")
    List<String> allowValueRegexes = new ArrayList<>();

    @Option(names = "--no-repo-config", negatable = true,
            description = "Ignora o .depguard.yml do repo (por padrão ele é lido e mesclado à allowlist).")
    boolean repoConfig = true;

    @Option(names = "--no-maven", negatable = true,
            description = "Resolve deps Maven via 'mvn dependency:tree' se houver pom.xml (roda o build; on por padrão na CLI).")
    boolean maven = true;

    @Option(names = "--upload", description = "Envia o resultado pro server (exige --server, --api-key, --project).")
    boolean uploadFlag;

    @Option(names = "--server", description = "URL base do server, ex.: http://localhost:8082")
    String serverUrl;

    @Option(names = "--api-key", description = "Chave de API (header X-Api-Key) pra autenticar o upload.")
    String apiKey;

    @Option(names = "--project", description = "ID do projeto no server que vai receber o scan.")
    String projectId;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final DepguardConfigLoader configLoader = new DepguardConfigLoader();

    @Override
    public Integer call() {
        if (uploadFlag && (isBlank(serverUrl) || isBlank(apiKey) || isBlank(projectId))) {
            System.err.println("--upload exige --server, --api-key e --project.");
            return 2;
        }
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
            // .depguard.yml do repo (checkout local = confiável): mesclado às flags.
            if (repoConfig) {
                allowlist = allowlist.merge(configLoader.load(repoRoot));
            }
            SecretScanMode secretMode = historyFlag ? SecretScanMode.GIT_HISTORY : SecretScanMode.WORKING_TREE;
            ScanRequest request = new ScanRequest(
                    repoRoot, engines, secretMode, allowlist, enrichFlag, java.util.List.of(),
                    verifySecretsFlag, maven);

            Scanner scanner = new DefaultScanner();
            ScanResult result = scanner.scan(request);

            String reportJson = new JsonReportWriter().write(result);
            Files.writeString(out.resolve("depguard-report.json"), reportJson);
            Files.writeString(out.resolve("depguard-report.sarif"), new SarifWriter().write(result));
            Files.writeString(out.resolve("depguard-sbom.cdx.json"), new CycloneDxWriter().write(result));

            printSummary(result, out);

            if (uploadFlag) {
                return uploadResult(reportJson);
            }
            return 0;
        } catch (Exception e) {
            System.err.println("Falha no scan: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Envia o mesmo JSON de {@code depguard-report.json} pro endpoint de
     * ingestão. Os relatórios locais já foram escritos antes daqui, então uma
     * falha de upload não perde o resultado do scan — só reporta o erro.
     */
    private Integer uploadResult(String reportJson) {
        String base = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        String url = base + "/api/v1/projects/" + projectId + "/scans/ingest";
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .header("X-Api-Key", apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(reportJson))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                System.err.println("Upload falhou (HTTP " + resp.statusCode() + "): " + resp.body());
                return 1;
            }
            System.out.println("  upload:           OK -> " + resp.body());
            return 0;
        } catch (Exception e) {
            System.err.println("Upload falhou: " + e.getMessage());
            return 1;
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
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
