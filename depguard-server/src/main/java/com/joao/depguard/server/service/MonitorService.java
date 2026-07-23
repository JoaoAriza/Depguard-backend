package com.joao.depguard.server.service;

import com.joao.depguard.core.deps.DependencyRechecker;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.server.dto.MonitorAlertDto;
import com.joao.depguard.server.dto.MonitorRecheckDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanComponent;
import com.joao.depguard.server.model.ScanStatus;
import com.joao.depguard.server.repository.MonitorAlertRepository;
import com.joao.depguard.server.repository.ProjectRepository;
import com.joao.depguard.server.repository.ScanComponentRepository;
import com.joao.depguard.server.repository.ScanRepository;
import com.joao.depguard.server.service.MonitorAlertService.ReconcileResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Monitoramento contínuo (docs/architecture.md §7). Re-corre só a etapa OSV
 * sobre as dependências que cada projeto já shipou — sem clonar nem parsear
 * nada — e detecta quando o OSV passou a conhecer uma vulnerabilidade nova
 * numa dep já em produção.
 *
 * <p><b>Fase 3a:</b> o re-check em si. <b>Fase 3b (este módulo):</b> a detecção
 * de "CVE novo vs. estado anterior" e a persistência dos alertas, delegadas ao
 * {@link MonitorAlertService} (bean separado pelo motivo do {@code @Transactional}
 * + proxy). A notificação é a 3c.
 *
 * <p>Sem {@code @Transactional} de propósito: o re-check faz I/O de rede
 * (OSV/EPSS/KEV) potencialmente lento, e segurar uma conexão de banco aberta
 * durante isso é justamente o que se quer evitar. Os componentes são lidos e
 * mapeados para {@link Component} (campos básicos, sem lazy) antes de qualquer
 * chamada externa; a reconciliação transacional acontece depois, no
 * {@link MonitorAlertService}.
 */
@Service
public class MonitorService {

    private static final Logger log = LoggerFactory.getLogger(MonitorService.class);

    private final ProjectRepository projectRepository;
    private final ScanRepository scanRepository;
    private final ScanComponentRepository scanComponentRepository;
    private final MonitorAlertRepository alertRepository;
    private final DependencyRechecker rechecker;
    private final MonitorAlertService alertService;

    public MonitorService(ProjectRepository projectRepository,
                          ScanRepository scanRepository,
                          ScanComponentRepository scanComponentRepository,
                          MonitorAlertRepository alertRepository,
                          DependencyRechecker rechecker,
                          MonitorAlertService alertService) {
        this.projectRepository = projectRepository;
        this.scanRepository = scanRepository;
        this.scanComponentRepository = scanComponentRepository;
        this.alertRepository = alertRepository;
        this.rechecker = rechecker;
        this.alertService = alertService;
    }

    /**
     * Trigger manual, escopado pela org do usuário. 404 tanto pra projeto
     * inexistente quanto pra projeto de outra org (não vaza existência);
     * 409 se o projeto ainda não tem nenhum scan concluído pra servir de
     * baseline.
     */
    public MonitorRecheckDto recheckProject(UUID projectId, AppUser user) {
        Project project = requireOwnedProject(projectId, user);
        return recheckProject(project)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT,
                        "Projeto ainda não tem scan concluído para monitorar."));
    }

    /** Alertas do projeto (mais recentes primeiro), escopado pela org do usuário. */
    public List<MonitorAlertDto> listAlerts(UUID projectId, AppUser user) {
        Project project = requireOwnedProject(projectId, user);
        return alertRepository.findByProjectOrderByDetectedAtDesc(project).stream()
                .map(MonitorAlertDto::from)
                .toList();
    }

    /**
     * Re-check + reconciliação de alertas de um projeto a partir do seu último
     * scan DONE. {@code empty} quando o projeto não tem nenhum scan concluído
     * (nada pra monitorar). Reusado tanto pelo trigger manual quanto pela
     * varredura agendada.
     */
    public Optional<MonitorRecheckDto> recheckProject(Project project) {
        Optional<Scan> baseline =
                scanRepository.findFirstByProjectAndStatusOrderByFinishedAtDesc(project, ScanStatus.DONE);
        if (baseline.isEmpty()) {
            return Optional.empty();
        }
        Scan scan = baseline.get();

        List<Component> components = scanComponentRepository.findByScan(scan).stream()
                .map(MonitorService::toCoreComponent)
                .toList();

        // Server sempre enriquece (EPSS/KEV) — igual ao ScanExecutionService — pra
        // que o alerta carregue a priorização por exploração.
        List<VulnFinding> current = rechecker.recheck(components, true);

        ReconcileResult reconcile = alertService.reconcile(project, scan, current);
        List<MonitorAlertDto> newAlerts = reconcile.newlyAlerted().stream()
                .map(MonitorAlertDto::from)
                .toList();

        return Optional.of(MonitorRecheckDto.of(
                project.getId(), scan.getId(), scan.getFinishedAt(),
                components.size(), current.size(), reconcile.resolvedCount(), newAlerts));
    }

    /**
     * Varredura agendada de todos os projetos (default: 03:00 diariamente).
     * Isola falha por projeto pra que um erro de rede num não aborte o resto.
     * Configurável via {@code depguard.monitor.cron} ({@code -} desativa).
     */
    @Scheduled(cron = "${depguard.monitor.cron:0 0 3 * * *}")
    public void recheckAllProjects() {
        List<Project> projects = projectRepository.findAll();
        log.info("Monitoramento contínuo: re-checando {} projeto(s).", projects.size());
        int rechecked = 0;
        int totalNew = 0;
        for (Project project : projects) {
            try {
                Optional<MonitorRecheckDto> result = recheckProject(project);
                if (result.isEmpty()) {
                    continue; // sem scan DONE: nada pra monitorar ainda
                }
                rechecked++;
                MonitorRecheckDto dto = result.get();
                totalNew += dto.newAlertCount();
                if (dto.newAlertCount() > 0 || dto.resolvedCount() > 0) {
                    log.info("Monitoramento: projeto {} — {} alerta(s) novo(s), {} resolvido(s) "
                                    + "({} vulnerabilidade(s) no re-check).",
                            project.getId(), dto.newAlertCount(), dto.resolvedCount(), dto.currentVulnCount());
                }
            } catch (Exception e) {
                log.warn("Monitoramento: falha ao re-checar projeto {}: {}", project.getId(), e.toString());
            }
        }
        log.info("Monitoramento contínuo: {} projeto(s) re-checado(s), {} alerta(s) novo(s) no total.",
                rechecked, totalNew);
    }

    private Project requireOwnedProject(UUID projectId, AppUser user) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));
        if (!project.getOrganization().getId().equals(user.getOrganization().getId())) {
            // 404 (não 403) de propósito: não vaza a existência de projetos de outra org.
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado.");
        }
        return project;
    }

    private static Component toCoreComponent(ScanComponent sc) {
        return new Component(
                sc.getEcosystem(),
                sc.getName(),
                sc.getVersion(),
                sc.getPurl(),
                sc.isDirect(),
                sc.getDepth(),
                sc.getLicenses() == null ? List.of() : sc.getLicenses());
    }
}
