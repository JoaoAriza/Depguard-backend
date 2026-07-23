package com.joao.depguard.server.dto;

import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.model.MonitorAlert;
import com.joao.depguard.server.model.MonitorAlertStatus;

import java.time.LocalDateTime;
import java.util.UUID;

/** Alerta de monitoramento contínuo (§7) para a API/UI. */
public record MonitorAlertDto(
        UUID id,
        String fingerprint,
        String osvId,
        String cve,
        Severity severity,
        String affectedPurl,
        String fixedVersion,
        Double epssScore,
        boolean kevListed,
        MonitorAlertStatus status,
        LocalDateTime detectedAt,
        LocalDateTime resolvedAt
) {
    public static MonitorAlertDto from(MonitorAlert a) {
        return new MonitorAlertDto(
                a.getId(), a.getFingerprint(), a.getOsvId(), a.getCve(), a.getSeverity(),
                a.getAffectedPurl(), a.getFixedVersion(), a.getEpssScore(), a.isKevListed(),
                a.getStatus(), a.getDetectedAt(), a.getResolvedAt());
    }
}
