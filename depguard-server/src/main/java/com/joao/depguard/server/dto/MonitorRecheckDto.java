package com.joao.depguard.server.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Resultado de um re-check de monitoramento (§7): re-corre o OSV sobre as
 * dependências que o projeto shipou no seu último scan concluído (o "baseline")
 * e reconcilia os alertas de CVE-novo.
 *
 * @param projectId          projeto re-checado
 * @param baselineScanId     scan DONE cujos componentes foram re-checados
 * @param baselineFinishedAt quando aquele scan terminou
 * @param componentsChecked  quantas dependências foram re-consultadas no OSV
 * @param currentVulnCount   total de vulnerabilidades no re-check
 * @param newAlertCount      alertas de CVE-novo criados/reabertos nesta execução
 * @param resolvedCount      alertas resolvidos nesta execução (CVE sumiu/foi absorvido)
 * @param newAlerts          os alertas novos desta execução (inéditos vs. baseline)
 */
public record MonitorRecheckDto(
        UUID projectId,
        UUID baselineScanId,
        LocalDateTime baselineFinishedAt,
        int componentsChecked,
        int currentVulnCount,
        int newAlertCount,
        int resolvedCount,
        List<MonitorAlertDto> newAlerts
) {
    public static MonitorRecheckDto of(UUID projectId, UUID baselineScanId, LocalDateTime baselineFinishedAt,
                                       int componentsChecked, int currentVulnCount,
                                       int resolvedCount, List<MonitorAlertDto> newAlerts) {
        return new MonitorRecheckDto(projectId, baselineScanId, baselineFinishedAt, componentsChecked,
                currentVulnCount, newAlerts.size(), resolvedCount, newAlerts);
    }
}
