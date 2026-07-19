package com.joao.depguard.server.controller;

import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.policy.PolicyDecision;
import com.joao.depguard.server.dto.ScanStatusDto;
import com.joao.depguard.server.dto.SubmitScanRequest;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.ScanTrigger;
import com.joao.depguard.server.model.TriageStatus;
import com.joao.depguard.server.service.FindingService;
import com.joao.depguard.server.service.PolicyService;
import com.joao.depguard.server.service.ScanExportService;
import com.joao.depguard.server.service.ScanService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
public class ScanController {

    private final ScanService scanService;
    private final ScanExportService scanExportService;
    private final PolicyService policyService;
    private final FindingService findingService;

    public ScanController(ScanService scanService,
                           ScanExportService scanExportService,
                           PolicyService policyService,
                           FindingService findingService) {
        this.scanService = scanService;
        this.scanExportService = scanExportService;
        this.policyService = policyService;
        this.findingService = findingService;
    }

    @PostMapping("/projects/{projectId}/scans")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public Map<String, UUID> submit(@PathVariable UUID projectId, @RequestBody SubmitScanRequest req) {
        Set<Engine> engines = (req.engines() == null || req.engines().isEmpty())
                ? EnumSet.allOf(Engine.class)
                : req.engines();
        UUID scanId = scanService.submit(projectId, Path.of(req.repoPath()), engines, ScanTrigger.MANUAL);
        return Map.of("scanId", scanId);
    }

    /**
     * Recebe um {@link ScanResult} já escaneado pela CLI (o mesmo JSON que a
     * CLI escreve em {@code depguard-report.json}) e o materializa no
     * dashboard. Autenticação via {@code X-Api-Key} (fluxo pensado pra CI) —
     * o escopo por org é resolvido em {@link ScanService#ingest}.
     */
    @PostMapping("/projects/{projectId}/scans/ingest")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, UUID> ingest(@PathVariable UUID projectId,
                                     @RequestBody ScanResult result,
                                     @AuthenticationPrincipal AppUser user) {
        UUID scanId = scanService.ingest(projectId, result, user);
        return Map.of("scanId", scanId);
    }

    @GetMapping("/scans/{id}")
    public ScanStatusDto status(@PathVariable UUID id) {
        return ScanStatusDto.from(scanService.getOrThrow(id));
    }

    @GetMapping("/projects/{projectId}/scans")
    public List<ScanStatusDto> listByProject(@PathVariable UUID projectId) {
        return scanService.listByProject(projectId).stream().map(ScanStatusDto::from).toList();
    }

    /** SBOM CycloneDX salvo verbatim no scan (não regenerado — evita qualquer risco de drift). */
    @GetMapping(value = "/scans/{id}/sbom", produces = MediaType.APPLICATION_JSON_VALUE)
    public String sbom(@PathVariable UUID id) {
        return scanExportService.sbom(id);
    }

    /**
     * SARIF é regenerado a partir dos {@code Finding}/{@code ScanComponent}
     * persistidos (via {@code SarifWriter} do core) — não guardamos um blob
     * SARIF separado, então não há como divergir do que está no banco.
     */
    @GetMapping(value = "/scans/{id}/sarif", produces = MediaType.APPLICATION_JSON_VALUE)
    public String sarif(@PathVariable UUID id) {
        return scanExportService.sarif(id);
    }

    /**
     * Resultado da policy pra este scan — o mesmo veredito que bloqueia (ou
     * não) um PR, mas visível fora do fluxo do GitHub: sem isso, quem olha um
     * scan no dashboard não tem como saber se ele passa na policy do projeto.
     *
     * <p>Aplica o mesmo filtro de triagem do fluxo de PR (FALSE_POSITIVE e
     * ACCEPTED_RISK não contam), pra não dar veredito diferente do que o PR
     * daria com os mesmos dados.
     */
    @GetMapping("/scans/{id}/policy-decision")
    public PolicyDecision policyDecision(@PathVariable UUID id) {
        var actionable = findingService.listByScan(id, null, null, null).stream()
                .filter(f -> f.triageStatus() != TriageStatus.FALSE_POSITIVE
                        && f.triageStatus() != TriageStatus.ACCEPTED_RISK)
                .toList();
        return policyService.evaluateForScan(id, actionable);
    }

    /** Relatório humano (PDFBox) — inclui triagem, ao contrário do SARIF/CycloneDX (formatos-padrão). */
    @GetMapping(value = "/scans/{id}/report.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> pdf(@PathVariable UUID id) {
        byte[] pdf = scanExportService.pdf(id);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename("depguard-scan-" + id + ".pdf").build().toString())
                .body(pdf);
    }
}
