package com.joao.depguard.server.service;

import com.joao.depguard.core.deps.DependencyRechecker;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.server.dto.MonitorRecheckDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanComponent;
import com.joao.depguard.server.model.ScanStatus;
import com.joao.depguard.server.repository.ProjectRepository;
import com.joao.depguard.server.repository.ScanComponentRepository;
import com.joao.depguard.server.repository.ScanRepository;
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
 * nada — para descobrir se o OSV passou a conhecer uma vulnerabilidade nova
 * numa dep já em produção.
 *
 * <p><b>Fase 3a (este módulo):</b> o re-check em si — extrair os componentes do
 * último scan DONE e reconsultar o OSV. A comparação "CVE novo vs. estado
 * anterior" e o alerta são a 3b; a notificação, a 3c.
 *
 * <p>Sem {@code @Transactional} de propósito: o re-check faz I/O de rede
 * (OSV/EPSS/KEV) potencialmente lento, e segurar uma conexão de banco aberta
 * durante isso é justamente o que se quer evitar. Os componentes são lidos e
 * mapeados para {@link Component} (campos básicos, sem lazy) antes de qualquer
 * chamada externa; nenhuma associação lazy é tocada fora de sessão.
 */
@Service
public class MonitorService {

    private static final Logger log = LoggerFactory.getLogger(MonitorService.class);

    private final ProjectRepository projectRepository;
    private final ScanRepository scanRepository;
    private final ScanComponentRepository scanComponentRepository;
    private final DependencyRechecker rechecker;

    public MonitorService(ProjectRepository projectRepository,
                          ScanRepository scanRepository,
                          ScanComponentRepository scanComponentRepository,
                          DependencyRechecker rechecker) {
        this.projectRepository = projectRepository;
        this.scanRepository = scanRepository;
        this.scanComponentRepository = scanComponentRepository;
        this.rechecker = rechecker;
    }

    /**
     * Trigger manual, escopado pela org do usuário. 404 tanto pra projeto
     * inexistente quanto pra projeto de outra org (não vaza existência);
     * 409 se o projeto ainda não tem nenhum scan concluído pra servir de
     * baseline.
     */
    public MonitorRecheckDto recheckProject(UUID projectId, AppUser user) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));
        if (!project.getOrganization().getId().equals(user.getOrganization().getId())) {
            // 404 (não 403) de propósito: não vaza a existência de projetos de outra org.
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado.");
        }
        return recheckProject(project)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT,
                        "Projeto ainda não tem scan concluído para monitorar."));
    }

    /**
     * Re-check de um projeto a partir do seu último scan DONE. {@code empty}
     * quando o projeto não tem nenhum scan concluído (nada pra monitorar).
     * Reusado tanto pelo trigger manual quanto pela varredura agendada.
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
        // que o alerta futuro (3b/3c) já carregue a priorização por exploração.
        List<VulnFinding> current = rechecker.recheck(components, true);

        return Optional.of(MonitorRecheckDto.of(
                project.getId(), scan.getId(), scan.getFinishedAt(), components.size(), current));
    }

    /**
     * Varredura agendada de todos os projetos (default: 03:00 diariamente).
     * Isola falha por projeto pra que um erro de rede num não aborte o resto.
     * Na Fase 3a só re-checa e loga; a detecção de CVE novo + alerta entram na
     * 3b. Configurável via {@code depguard.monitor.cron} ({@code -} desativa).
     */
    @Scheduled(cron = "${depguard.monitor.cron:0 0 3 * * *}")
    public void recheckAllProjects() {
        List<Project> projects = projectRepository.findAll();
        log.info("Monitoramento contínuo: re-checando {} projeto(s).", projects.size());
        int rechecked = 0;
        for (Project project : projects) {
            try {
                Optional<MonitorRecheckDto> result = recheckProject(project);
                if (result.isEmpty()) {
                    continue; // sem scan DONE: nada pra monitorar ainda
                }
                rechecked++;
                MonitorRecheckDto dto = result.get();
                log.info("Monitoramento: projeto {} — {} componente(s), {} vulnerabilidade(s) no re-check.",
                        project.getId(), dto.componentsChecked(), dto.currentVulnCount());
            } catch (Exception e) {
                log.warn("Monitoramento: falha ao re-checar projeto {}: {}", project.getId(), e.toString());
            }
        }
        log.info("Monitoramento contínuo: {} projeto(s) re-checado(s).", rechecked);
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
