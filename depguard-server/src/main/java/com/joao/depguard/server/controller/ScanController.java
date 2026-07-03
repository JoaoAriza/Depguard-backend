package com.joao.depguard.server.controller;

import com.joao.depguard.core.model.Engine;
import com.joao.depguard.server.dto.ScanStatusDto;
import com.joao.depguard.server.dto.SubmitScanRequest;
import com.joao.depguard.server.model.ScanTrigger;
import com.joao.depguard.server.service.ScanService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Só o essencial pra provar o pipeline assíncrono (Passo 6d). Listagem de
 * findings/SBOM/SARIF por endpoint dedicado é Passo 7
 * (docs/architecture.md §8) — aqui só o suficiente pra disparar e consultar
 * status.
 */
@RestController
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
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
}
