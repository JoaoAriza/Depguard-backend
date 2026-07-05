package com.joao.depguard.server.controller;

import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.dto.FindingDto;
import com.joao.depguard.server.dto.TriageRequest;
import com.joao.depguard.server.model.TriageStatus;
import com.joao.depguard.server.service.FindingService;
import com.joao.depguard.server.service.FindingTriageService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
public class FindingController {

    private final FindingService findingService;
    private final FindingTriageService findingTriageService;

    public FindingController(FindingService findingService, FindingTriageService findingTriageService) {
        this.findingService = findingService;
        this.findingTriageService = findingTriageService;
    }

    @GetMapping("/scans/{scanId}/findings")
    public List<FindingDto> byScan(@PathVariable UUID scanId,
                                    @RequestParam(required = false) FindingType type,
                                    @RequestParam(required = false) Severity severity,
                                    @RequestParam(required = false) TriageStatus status) {
        return findingService.listByScan(scanId, type, severity, status);
    }

    @GetMapping("/projects/{projectId}/findings")
    public List<FindingDto> currentByProject(@PathVariable UUID projectId) {
        return findingService.listCurrentByProject(projectId);
    }

    /**
     * Path aninhado em {@code {projectId}}, diferente do esboço original do
     * doc ({@code POST /findings/{fingerprint}/triage}): FindingTriage é
     * chaveado por (project, fingerprint) — ver docs/architecture.md §4.1 —
     * então um fingerprint sozinho não identifica a linha de triagem sem o
     * projeto.
     */
    @PostMapping("/projects/{projectId}/findings/{fingerprint}/triage")
    public void triage(@PathVariable UUID projectId, @PathVariable String fingerprint,
                        @RequestBody TriageRequest req) {
        findingTriageService.upsert(projectId, fingerprint, req);
    }
}
