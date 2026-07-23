package com.joao.depguard.server.controller;

import com.joao.depguard.server.dto.MonitorRecheckDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.service.MonitorService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * Monitoramento contínuo (§7). Na Fase 3a expõe só o trigger manual do
 * re-check — o mesmo que a varredura agendada roda — para verificação ao vivo
 * e para forçar uma checagem sob demanda. Escopado pela org do usuário.
 */
@RestController
@RequestMapping("/api/v1")
public class MonitorController {

    private final MonitorService monitorService;

    public MonitorController(MonitorService monitorService) {
        this.monitorService = monitorService;
    }

    @PostMapping("/projects/{projectId}/monitor/recheck")
    public MonitorRecheckDto recheck(@PathVariable UUID projectId,
                                     @AuthenticationPrincipal AppUser user) {
        return monitorService.recheckProject(projectId, user);
    }
}
