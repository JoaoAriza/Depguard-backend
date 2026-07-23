package com.joao.depguard.server.dto;

import com.joao.depguard.core.model.VulnFinding;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Resultado de um re-check de monitoramento (§7): o estado ATUAL de
 * vulnerabilidades do OSV para as dependências que o projeto shipou no seu
 * último scan concluído (o "baseline"). Na Fase 3a isto é só informativo — a
 * detecção de "CVE novo vs. estado anterior" e o alerta entram na 3b.
 *
 * @param projectId          projeto re-checado
 * @param baselineScanId     scan DONE cujos componentes foram re-checados
 * @param baselineFinishedAt quando aquele scan terminou
 * @param componentsChecked  quantas dependências foram re-consultadas no OSV
 * @param currentVulnCount   total de vulnerabilidades no re-check
 * @param currentVulns       as vulnerabilidades atuais (com fingerprint estável)
 */
public record MonitorRecheckDto(
        UUID projectId,
        UUID baselineScanId,
        LocalDateTime baselineFinishedAt,
        int componentsChecked,
        int currentVulnCount,
        List<VulnFinding> currentVulns
) {
    public static MonitorRecheckDto of(UUID projectId, UUID baselineScanId,
                                       LocalDateTime baselineFinishedAt,
                                       int componentsChecked, List<VulnFinding> currentVulns) {
        return new MonitorRecheckDto(projectId, baselineScanId, baselineFinishedAt,
                componentsChecked, currentVulns.size(), currentVulns);
    }
}
