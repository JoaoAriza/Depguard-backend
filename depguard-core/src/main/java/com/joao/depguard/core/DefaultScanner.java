package com.joao.depguard.core;

import com.joao.depguard.core.deps.NpmLockfileParser;
import com.joao.depguard.core.deps.epss.EpssApi;
import com.joao.depguard.core.deps.epss.EpssClient;
import com.joao.depguard.core.deps.kev.KevApi;
import com.joao.depguard.core.deps.kev.KevClient;
import com.joao.depguard.core.deps.osv.OsvApi;
import com.joao.depguard.core.deps.osv.OsvClient;
import com.joao.depguard.core.deps.osv.OsvVulnerabilityScanner;
import com.joao.depguard.core.deps.priority.ExploitabilityEnricher;
import com.joao.depguard.core.deps.pypi.PoetryLockParser;
import com.joao.depguard.core.deps.pypi.RequirementsTxtParser;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.ScanMeta;
import com.joao.depguard.core.model.ScanRequest;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.SecretScanMode;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.secrets.WorkingTreeSecretScanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Implementação de referência do {@link Scanner}, usada pela CLI e pelo
 * worker do servidor.
 *
 * <p>Engine A (Fase 1): npm via {@code package-lock.json} e PyPI via
 * {@code poetry.lock} (caminho feliz) ou {@code requirements.txt} (fallback
 * best-effort, sempre marca {@code partial}) — docs/architecture.md §2.1.
 * Maven fica de fora do MVP (sem lockfile próprio — ver docs §2.1). Engine B
 * cobre apenas o modo {@link SecretScanMode#WORKING_TREE}; histórico git é
 * o Passo 9, ainda não ligado aqui.
 */
public class DefaultScanner implements Scanner {

    private final NpmLockfileParser npmLockfileParser = new NpmLockfileParser();
    private final PoetryLockParser poetryLockParser = new PoetryLockParser();
    private final RequirementsTxtParser requirementsTxtParser = new RequirementsTxtParser();
    private final WorkingTreeSecretScanner secretScanner = new WorkingTreeSecretScanner();
    private final OsvApi osvApi;
    private final EpssApi epssApi;
    private final KevApi kevApi;

    public DefaultScanner() {
        this(new OsvClient(), new EpssClient(), new KevClient());
    }

    /** Permite injetar um {@link OsvApi} fake em testes, sem tocar a rede. */
    public DefaultScanner(OsvApi osvApi) {
        this(osvApi, new EpssClient(), new KevClient());
    }

    public DefaultScanner(OsvApi osvApi, EpssApi epssApi, KevApi kevApi) {
        this.osvApi = osvApi;
        this.epssApi = epssApi;
        this.kevApi = kevApi;
    }

    @Override
    public ScanResult scan(ScanRequest request) {
        long startNanos = System.nanoTime();
        Set<String> ecosystems = new LinkedHashSet<>();

        List<Component> components = new ArrayList<>();
        List<VulnFinding> vulnFindings = List.of();
        boolean partial = false;

        if (request.engines().contains(Engine.DEPENDENCIES)) {
            Path npmLock = request.repoRoot().resolve("package-lock.json");
            if (Files.isRegularFile(npmLock)) {
                components.addAll(npmLockfileParser.parse(npmLock));
                ecosystems.add("npm");
            } else {
                partial = true; // sem lockfile npm: resultado incompleto (docs §2.1)
            }

            Path poetryLock = request.repoRoot().resolve("poetry.lock");
            Path requirementsTxt = request.repoRoot().resolve("requirements.txt");
            if (Files.isRegularFile(poetryLock)) {
                components.addAll(poetryLockParser.parse(poetryLock));
                ecosystems.add("pypi");
            } else if (Files.isRegularFile(requirementsTxt)) {
                components.addAll(requirementsTxtParser.parse(requirementsTxt));
                ecosystems.add("pypi");
                // requirements.txt não garante fechamento transitivo completo
                // (só pins exatos são extraídos) — sempre parcial (docs §2.1).
                partial = true;
            }

            if (!components.isEmpty()) {
                vulnFindings = new OsvVulnerabilityScanner(osvApi).scan(components);
                if (request.enrichExploitability() && !vulnFindings.isEmpty()) {
                    vulnFindings = new ExploitabilityEnricher(epssApi, kevApi).enrich(vulnFindings);
                }
            }
        }

        List<SecretFinding> secretFindings = List.of();
        if (request.engines().contains(Engine.SECRETS)) {
            if (request.secretMode() != SecretScanMode.WORKING_TREE) {
                throw new UnsupportedOperationException(
                        "Modo " + request.secretMode()
                                + " ainda não implementado (ver docs/architecture.md §8, Passo 9).");
            }
            secretFindings = secretScanner.scan(request.repoRoot(), request.allowlist());
        }

        long durationMillis = (System.nanoTime() - startNanos) / 1_000_000;
        ScanMeta meta = new ScanMeta(partial, ecosystems, durationMillis);
        return new ScanResult(components, vulnFindings, secretFindings, meta);
    }
}
