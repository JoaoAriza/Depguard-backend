package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanStatus;

import java.time.LocalDateTime;
import java.util.UUID;

public record ScanStatusDto(
        UUID id, ScanStatus status, boolean partial, LocalDateTime createdAt,
        LocalDateTime startedAt, LocalDateTime finishedAt, String summary
) {
    public static ScanStatusDto from(Scan s) {
        return new ScanStatusDto(s.getId(), s.getStatus(), s.isPartial(), s.getCreatedAt(),
                s.getStartedAt(), s.getFinishedAt(), s.getSummary());
    }
}
