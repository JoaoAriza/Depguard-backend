package com.joao.depguard.server.controller;

import com.joao.depguard.server.dto.MonitorAlertDto;
import com.joao.depguard.server.dto.MonitorRecheckDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.service.MonitorService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Monitoramento contínuo (§7). Expõe o trigger manual do re-check — o mesmo que
 * a varredura agendada roda — e a listagem de alertas de CVE-novo do projeto.
 * Tudo escopado pela org do usuário.
 */
@RestController
@RequestMapping("/api/v1")
public class MonitorController {

    private final MonitorService monitorService;

    public MonitorController(MonitorService monitorService) {
        this.monitorService = monitorService;
    }

    /** Força um re-check agora e reconcilia os alertas; retorna os alertas novos desta execução. */
    @PostMapping("/projects/{projectId}/monitor/recheck")
    public MonitorRecheckDto recheck(@PathVariable UUID projectId,
                                     @AuthenticationPrincipal AppUser user) {
        return monitorService.recheckProject(projectId, user);
    }

    /** Alertas de CVE-novo do projeto (OPEN e RESOLVED), mais recentes primeiro. */
    @GetMapping("/projects/{projectId}/monitor/alerts")
    public List<MonitorAlertDto> alerts(@PathVariable UUID projectId,
                                        @AuthenticationPrincipal AppUser user) {
        return monitorService.listAlerts(projectId, user);
    }
}
