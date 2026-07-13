package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.dto.FindingDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Finding;
import com.joao.depguard.server.model.FindingTriage;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanStatus;
import com.joao.depguard.server.model.TriageStatus;
import com.joao.depguard.server.repository.FindingRepository;
import com.joao.depguard.server.repository.FindingTriageRepository;
import com.joao.depguard.server.repository.ProjectRepository;
import com.joao.depguard.server.repository.ScanRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class FindingService {

    private final ScanRepository scanRepository;
    private final ProjectRepository projectRepository;
    private final FindingRepository findingRepository;
    private final FindingTriageRepository findingTriageRepository;
    private final ObjectMapper mapper;

    public FindingService(ScanRepository scanRepository,
                           ProjectRepository projectRepository,
                           FindingRepository findingRepository,
                           FindingTriageRepository findingTriageRepository,
                           ObjectMapper mapper) {
        this.scanRepository = scanRepository;
        this.projectRepository = projectRepository;
        this.findingRepository = findingRepository;
        this.findingTriageRepository = findingTriageRepository;
        this.mapper = mapper;
    }

    public List<FindingDto> listByScan(UUID scanId, FindingType type, Severity severity, TriageStatus status) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan não encontrado."));

        List<Finding> findings = findingRepository.findByScan(scan).stream()
                .filter(f -> type == null || f.getType() == type)
                .filter(f -> severity == null || f.getSeverity() == severity)
                .toList();

        return assemble(scan.getProject(), findings, status);
    }

    /**
     * "Estado atual" do projeto = findings do scan DONE mais recente (docs
     * §5). Snapshot simples pro MVP — vira mais rico com o monitoramento
     * contínuo (§7 do doc).
     */
    public List<FindingDto> listCurrentByProject(UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));

        return scanRepository.findFirstByProjectAndStatusOrderByFinishedAtDesc(project, ScanStatus.DONE)
                .map(latest -> assemble(project, findingRepository.findByScan(latest), null))
                .orElse(List.of());
    }

    private List<FindingDto> assemble(Project project, List<Finding> findings, TriageStatus statusFilter) {
        List<String> fingerprints = findings.stream().map(Finding::getFingerprint).toList();
        Map<String, FindingTriage> triageByFingerprint = new HashMap<>();
        for (FindingTriage t : findingTriageRepository.findByProjectAndFingerprintIn(project, fingerprints)) {
            triageByFingerprint.put(t.getFingerprint(), t);
        }

        List<FindingDto> result = new ArrayList<>();
        for (Finding f : findings) {
            FindingTriage triage = triageByFingerprint.get(f.getFingerprint());
            TriageStatus triageStatus = triage != null ? triage.getStatus() : TriageStatus.OPEN;
            if (statusFilter != null && statusFilter != triageStatus) {
                continue;
            }
            AppUser assignee = triage != null ? triage.getAssignee() : null;
            result.add(new FindingDto(f.getId(), f.getType(), f.getSeverity(), f.getFingerprint(),
                    readTree(f.getDetail()), triageStatus, triage != null ? triage.getNote() : null,
                    assignee != null ? assignee.getId() : null, assignee != null ? assignee.getName() : null));
        }
        return result;
    }

    private JsonNode readTree(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao ler detail persistido", e);
        }
    }
}
