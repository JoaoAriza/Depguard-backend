package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.ApiKey;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Não é record: {@code plainKey} é preenchido depois da construção, só na
 * resposta de criação. Sem {@code toString}/{@code equals} gerados de
 * propósito (evita vazar {@code plainKey} em log via Lombok {@code @Data}).
 */
@Getter
@Setter
@Builder
public class ApiKeyDto {

    private UUID id;
    private String name;
    private String keyPrefix;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
    private LocalDateTime revokedAt;
    private LocalDateTime expiresAt;
    private boolean active;
    private String createdByName;

    /** Chave completa — preenchida APENAS na resposta de criação. */
    private String plainKey;

    public static ApiKeyDto from(ApiKey k) {
        return ApiKeyDto.builder()
                .id(k.getId())
                .name(k.getName())
                .keyPrefix(k.getKeyPrefix())
                .createdAt(k.getCreatedAt())
                .lastUsedAt(k.getLastUsedAt())
                .revokedAt(k.getRevokedAt())
                .expiresAt(k.getExpiresAt())
                .active(k.isActive())
                .createdByName(k.getCreatedBy() != null ? k.getCreatedBy().getName() : null)
                .build();
    }
}
