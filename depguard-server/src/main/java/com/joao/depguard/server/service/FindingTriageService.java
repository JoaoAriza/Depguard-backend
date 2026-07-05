package com.joao.depguard.server.service;

import com.joao.depguard.server.dto.TriageRequest;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.FindingTriage;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.repository.AppUserRepository;
import com.joao.depguard.server.repository.FindingTriageRepository;
import com.joao.depguard.server.repository.ProjectRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Chaveado por (project, fingerprint) — NÃO por finding.id — pra um re-scan
 * não apagar a triagem já feita (docs/architecture.md §4.1).
 */
@Service
public class FindingTriageService {

    private final ProjectRepository projectRepository;
    private final FindingTriageRepository findingTriageRepository;
    private final AppUserRepository appUserRepository;

    public FindingTriageService(ProjectRepository projectRepository,
                                 FindingTriageRepository findingTriageRepository,
                                 AppUserRepository appUserRepository) {
        this.projectRepository = projectRepository;
        this.findingTriageRepository = findingTriageRepository;
        this.appUserRepository = appUserRepository;
    }

    @Transactional
    public FindingTriage upsert(UUID projectId, String fingerprint, TriageRequest req) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));

        FindingTriage triage = findingTriageRepository.findByProjectAndFingerprint(project, fingerprint)
                .orElseGet(() -> FindingTriage.builder()
                        .project(project)
                        .fingerprint(fingerprint)
                        .build());

        triage.setStatus(req.status());
        triage.setNote(req.note());
        triage.setUpdatedAt(LocalDateTime.now());

        if (req.assigneeId() != null) {
            AppUser assignee = appUserRepository.findById(req.assigneeId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado."));
            triage.setAssignee(assignee);
        }

        return findingTriageRepository.save(triage);
    }
}
