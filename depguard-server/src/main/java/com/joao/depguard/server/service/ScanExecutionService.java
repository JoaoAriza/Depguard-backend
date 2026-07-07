package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.Scanner;
import com.joao.depguard.core.model.Allowlist;
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
import com.joao.depguard.server.model.Sbom;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanComponent;
import com.joao.depguard.server.model.ScanStatus;
import com.joao.depguard.server.repository.FindingRepository;
import com.joao.depguard.server.repository.SbomRepository;
import com.joao.depguard.server.repository.ScanComponentRepository;
import com.joao.depguard.server.repository.ScanRepository;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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
    private final SbomRepository sbomRepository;
    private final Scanner scanner;
    private final ObjectMapper mapper = new ObjectMapper();
    private final CycloneDxWriter cycloneDxWriter = new CycloneDxWriter();

    public ScanExecutionService(ScanRepository scanRepository,
                                 ScanComponentRepository scanComponentRepository,
                                 FindingRepository findingRepository,
                                 SbomRepository sbomRepository,
                                 Scanner scanner) {
        this.scanRepository = scanRepository;
        this.scanComponentRepository = scanComponentRepository;
        this.findingRepository = findingRepository;
        this.sbomRepository = sbomRepository;
        this.scanner = scanner;
    }

    @Async
    public void executeAsync(UUID scanId, Path repoRoot, Set<Engine> engines) {
        markRunning(scanId);
        try {
            // Diferente da CLI (opt-in via --enrich, pra iteração local rápida):
            // scans do servidor alimentam triagem/dashboard, onde priorização por
            // EPSS/KEV importa mais que os ~1-2s extras de rede.
            ScanRequest request = new ScanRequest(
                    repoRoot, engines, SecretScanMode.WORKING_TREE, Allowlist.empty(), true);
            ScanResult result = scanner.scan(request);
            persistResult(scanId, result);
        } catch (Exception e) {
            markFailed(scanId);
        }
    }

    @Transactional
    void markRunning(UUID scanId) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.RUNNING);
        scan.setStartedAt(LocalDateTime.now());
        scanRepository.save(scan);
    }

    @Transactional
    void markFailed(UUID scanId) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        scan.setStatus(ScanStatus.FAILED);
        scan.setFinishedAt(LocalDateTime.now());
        scanRepository.save(scan);
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
