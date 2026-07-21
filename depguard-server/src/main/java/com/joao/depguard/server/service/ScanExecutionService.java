package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.Scanner;
import com.joao.depguard.core.config.DepguardConfigLoader;
import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.ChangedFile;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.ScanRequest;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.SecretScanMode;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.report.CycloneDxWriter;
import com.joao.depguard.server.model.Finding;
import com.joao.depguard.server.model.FindingTriage;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Sbom;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanComponent;
import com.joao.depguard.server.model.ScanStatus;
import com.joao.depguard.server.model.TriageStatus;
import com.joao.depguard.server.repository.FindingRepository;
import com.joao.depguard.server.repository.FindingTriageRepository;
import com.joao.depguard.server.repository.SbomRepository;
import com.joao.depguard.server.repository.ScanComponentRepository;
import com.joao.depguard.server.repository.ScanRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Executa o scan em background e persiste o resultado. Fica em bean
 * SEPARADO de {@link ScanService} de propósito: {@code @Async} só funciona
 * através do proxy do Spring — chamar um método {@code @Async} de dentro da
 * mesma classe (self-invocation) faz ele rodar síncrono, silenciosamente.
 */
@Service
public class ScanExecutionService {

    private final ScanRepository scanRepository;
    private final ScanComponentRepository scanComponentRepository;
    private final FindingRepository findingRepository;
    private final FindingTriageRepository findingTriageRepository;
    private final SbomRepository sbomRepository;
    private final Scanner scanner;
    private final PolicyService policyService;
    private final ObjectMapper mapper = new ObjectMapper();
    private final CycloneDxWriter cycloneDxWriter = new CycloneDxWriter();
    private final DepguardConfigLoader configLoader = new DepguardConfigLoader();

    public ScanExecutionService(ScanRepository scanRepository,
                                 ScanComponentRepository scanComponentRepository,
                                 FindingRepository findingRepository,
                                 FindingTriageRepository findingTriageRepository,
                                 SbomRepository sbomRepository,
                                 Scanner scanner,
                                 PolicyService policyService) {
        this.scanRepository = scanRepository;
        this.scanComponentRepository = scanComponentRepository;
        this.findingRepository = findingRepository;
        this.findingTriageRepository = findingTriageRepository;
        this.sbomRepository = sbomRepository;
        this.scanner = scanner;
        this.policyService = policyService;
    }

    @Async
    public void executeAsync(UUID scanId, Path repoRoot, Set<Engine> engines) {
        runSync(scanId, repoRoot, engines);
    }

    /**
     * Mesma lógica de {@link #executeAsync}, mas SEM {@code @Async} — pra
     * quem já está rodando numa thread de background própria (ex.:
     * {@code GithubPullRequestScanOrchestrator}) e só precisaria de uma
     * segunda camada de {@code @Async} por acidente, sem ganho nenhum.
     *
     * @return true se o scan terminou com sucesso (status DONE)
     */
    public boolean runSync(UUID scanId, Path repoRoot, Set<Engine> engines) {
        return runSync(scanId, repoRoot, engines, SecretScanMode.WORKING_TREE, List.of());
    }

    /**
     * Variante usada pelo fluxo de PR do GitHub App: segredos em modo
     * {@link SecretScanMode#PR_DIFF} (só as linhas que o PR adiciona — não
     * reacusa segredo pré-existente que o PR não tocou), com dependências
     * ainda escaneadas no clone completo (lockfile precisa da árvore
     * inteira, não dá pra resolver a partir só do diff).
     */
    public boolean runSync(UUID scanId, Path repoRoot, Set<Engine> engines,
                            SecretScanMode secretMode, List<ChangedFile> changedFiles) {
        Project project = markRunning(scanId);
        try {
            // Diferente da CLI (opt-in via --enrich, pra iteração local rápida):
            // scans do servidor alimentam triagem/dashboard, onde priorização por
            // EPSS/KEV importa mais que os ~1-2s extras de rede.
            // Verificação ao vivo é opt-in por projeto, guardada na policy (§3.3).
            boolean verifySecrets = policyService.rulesFor(project).verifySecrets();
            ScanRequest request = new ScanRequest(
                    repoRoot, engines, secretMode, buildAllowlist(project, repoRoot, secretMode),
                    true, changedFiles, verifySecrets);
            ScanResult result = scanner.scan(request);
            persistResult(scanId, result);
            return true;
        } catch (Exception e) {
            markFailed(scanId);
            return false;
        }
    }

    /**
     * Allowlist efetiva do scan: triagem FALSE_POSITIVE (fingerprints) +, em
     * checkout CONFIÁVEL, o {@code .depguard.yml} do repo.
     *
     * <p>Segredos FALSE_POSITIVE não voltam nos próximos scans — reaproveita o
     * {@code AllowlistMatcher} do core. Vulnerabilidades não passam por aqui
     * (o scanner de dependências ainda não consulta Allowlist).
     *
     * <p><b>PR_DIFF NÃO lê o {@code .depguard.yml}</b>: o checkout é o head do
     * PR, potencialmente de um contribuidor não-confiável que poderia
     * allowlistar no mesmo PR o segredo que está introduzindo. Checkout
     * completo (WORKING_TREE/GIT_HISTORY) é o código do dono — confiável.
     */
    private Allowlist buildAllowlist(Project project, Path repoRoot, SecretScanMode secretMode) {
        Set<String> fingerprints = findingTriageRepository.findByProjectAndStatus(project, TriageStatus.FALSE_POSITIVE)
                .stream()
                .map(FindingTriage::getFingerprint)
                .collect(Collectors.toSet());
        Allowlist triage = new Allowlist(Set.of(), Set.of(), fingerprints);

        if (!honorsRepoConfig(secretMode)) {
            return triage;
        }
        return triage.merge(configLoader.load(repoRoot));
    }

    /**
     * Se o {@code .depguard.yml} do checkout deve ser respeitado. Fronteira de
     * confiança: PR_DIFF escaneia o head de um PR possivelmente de contribuidor
     * não-confiável, que poderia allowlistar no mesmo PR o segredo que
     * introduz — então NÃO. Checkout completo (WORKING_TREE/GIT_HISTORY) é o
     * código do dono do projeto, confiável.
     */
    static boolean honorsRepoConfig(SecretScanMode secretMode) {
        return secretMode != SecretScanMode.PR_DIFF;
    }

    @Transactional
    Project markRunning(UUID scanId) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(LocalDateTime.now());
        scanRepository.save(scan);
        return scan.getProject();
    }

    @Transactional
    void markFailed(UUID scanId) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.FAILED);
        scan.setFinishedAt(LocalDateTime.now());
        scanRepository.save(scan);
    }

    /**
     * Persiste um {@link ScanResult} já pronto — vindo da CLI via upload, não
     * rodado aqui. Reaproveita exatamente a mesma persistência do fluxo do
     * dashboard/PR ({@link #persistResult}), então um scan de CLI aparece no
     * dashboard idêntico a um scan disparado pelo server.
     */
    public void ingestResult(UUID scanId, ScanResult result) {
        persistResult(scanId, result);
    }

    @Transactional
    void persistResult(UUID scanId, ScanResult result) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();

        for (Component c : result.components()) {
            scanComponentRepository.save(ScanComponent.builder()
                    .scan(scan)
                    .ecosystem(c.ecosystem())
                    .name(c.name())
                    .version(c.version())
                    .purl(c.purl())
                    .direct(c.direct())
                    .depth(c.depth())
                    .licenses(c.licenses())
                    .build());
        }

        for (VulnFinding vf : result.vulnFindings()) {
            findingRepository.save(Finding.builder()
                    .scan(scan)
                    .type(FindingType.DEPENDENCY_VULN)
                    .fingerprint(vf.fingerprint())
                    .severity(vf.severity())
                    .detail(writeJson(vf))
                    .build());
        }

        for (SecretFinding sf : result.secretFindings()) {
            findingRepository.save(Finding.builder()
                    .scan(scan)
                    .type(FindingType.SECRET)
                    .fingerprint(sf.fingerprint())
                    .severity(null)
                    .detail(writeJson(sf))
                    .build());
        }

        if (!result.components().isEmpty()) {
            sbomRepository.save(Sbom.builder()
                    .scan(scan)
                    .format("CycloneDX")
                    .specVersion("1.5")
                    .document(cycloneDxWriter.write(result))
                    .build());
        }

        scan.setStatus(ScanStatus.DONE);
        scan.setPartial(result.meta().partial());
        scan.setFinishedAt(LocalDateTime.now());
        scan.setSummary(writeJson(Map.of(
                "components", result.components().size(),
                "vulnFindings", result.vulnFindings().size(),
                "secretFindings", result.secretFindings().size(),
                "durationMillis", result.meta().durationMillis()
        )));
        scanRepository.save(scan);
    }

    private String writeJson(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao serializar para jsonb", e);
        }
    }
}
