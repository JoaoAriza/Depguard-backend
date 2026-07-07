package com.joao.depguard.server.controller;

import com.joao.depguard.core.model.Engine;
import com.joao.depguard.server.dto.ScanStatusDto;
import com.joao.depguard.server.dto.SubmitScanRequest;
import com.joao.depguard.server.model.ScanTrigger;
import com.joao.depguard.server.service.ScanExportService;
import com.joao.depguard.server.service.ScanService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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

    public ScanController(ScanService scanService, ScanExportService scanExportService) {
        this.scanService = scanService;
        this.scanExportService = scanExportService;
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
}
