package com.joao.depguard.server.service;

import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.server.model.AppUser;
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
import java.time.LocalDateTime;
import java.util.List;
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

        UUID scanId = createQueued(project, trigger);
        executionService.executeAsync(scanId, repoRoot, engines);
        return scanId;
    }

    /**
     * Só cria a linha QUEUED e commita — não dispara nenhum scan. Usado pelo
     * fluxo do GitHub App, que ainda precisa clonar o repo (fora deste
     * método) antes de rodar {@code ScanExecutionService.runSync}.
     */
    public UUID createQueued(Project project, ScanTrigger trigger) {
        Scan scan = Scan.builder()
                .project(project)
                .trigger(trigger)
                .status(ScanStatus.QUEUED)
                .partial(false)
                .createdAt(LocalDateTime.now())
                .build();
        return scanRepository.save(scan).getId();
    }

    /**
     * Recebe um {@link ScanResult} já escaneado pela CLI e o persiste como um
     * scan concluído (trigger CLI). Ao contrário de {@link #submit}, não roda
     * nada — o scan aconteceu na máquina de quem chamou; aqui só materializa o
     * resultado no dashboard.
     *
     * <p>Escopado pela organização do dono da chave de API: uma chave da org A
     * não pode injetar findings num projeto da org B.
     */
    public UUID ingest(UUID projectId, ScanResult result, AppUser user) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));
        if (!project.getOrganization().getId().equals(user.getOrganization().getId())) {
            // 404 (não 403) de propósito: não vaza a existência de projetos de outra org.
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado.");
        }

        UUID scanId = createQueued(project, ScanTrigger.CLI);
        executionService.ingestResult(scanId, result);
        return scanId;
    }

    public Scan getOrThrow(UUID scanId) {
        return scanRepository.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan não encontrado."));
    }

    public List<Scan> listByProject(UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));
        return scanRepository.findByProjectOrderByCreatedAtDesc(project);
    }
}
