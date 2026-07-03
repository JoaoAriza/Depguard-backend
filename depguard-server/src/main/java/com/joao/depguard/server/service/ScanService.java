package com.joao.depguard.server.service;

import com.joao.depguard.core.model.Engine;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanStatus;
import com.joao.depguard.server.model.ScanTrigger;
import com.joao.depguard.server.repository.ProjectRepository;
import com.joao.depguard.server.repository.ScanRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;

@Service
public class ScanService {

    private final ProjectRepository projectRepository;
    private final ScanRepository scanRepository;
    private final ScanExecutionService executionService;

    public ScanService(ProjectRepository projectRepository,
                        ScanRepository scanRepository,
                        ScanExecutionService executionService) {
        this.projectRepository = projectRepository;
        this.scanRepository = scanRepository;
        this.executionService = executionService;
    }

    /**
     * De propósito SEM {@code @Transactional} neste método: {@code executeAsync}
     * roda numa thread separada que lê o {@code Scan} por outra conexão. Um
     * {@code @Transactional} aqui só commitaria quando {@code submit} retornasse
     * — DEPOIS do disparo assíncrono — e a outra thread não enxergaria a linha
     * ainda (READ COMMITTED). Confirmado na prática com
     * {@code NoSuchElementException} na thread assíncrona.
     *
     * <p>{@code scanRepository.save(...)} já commita sozinho ao retornar (é a
     * transação própria e default do Spring Data JPA para aquele método) —
     * não depende de nenhum {@code @Transactional} deste método. Por isso a
     * linha já está garantidamente commitada antes do {@code executeAsync}.
     */
    public UUID submit(UUID projectId, Path repoRoot, Set<Engine> engines, ScanTrigger trigger) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));

        Scan scan = Scan.builder()
                .project(project)
                .trigger(trigger)
                .status(ScanStatus.QUEUED)
                .partial(false)
                .build();
        UUID scanId = scanRepository.save(scan).getId();

        executionService.executeAsync(scanId, repoRoot, engines);
        return scanId;
    }

    public Scan getOrThrow(UUID scanId) {
        return scanRepository.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan não encontrado."));
    }
}
