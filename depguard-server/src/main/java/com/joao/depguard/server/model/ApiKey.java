package com.joao.depguard.server.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * API Key para acesso programático (CLI/CI). Fork do padrão do CyberAudit:
 * só o hash BCrypt é persistido; a chave completa só existe na resposta de
 * criação. Formato: {@code dg_<32 hex chars>}.
 */
@Entity
@Table(name = "api_keys")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKey {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 100)
    private String name;

    /** Prefixo exibível — "dg_" + 8 hex chars. */
    @Column(nullable = false, length = 16)
    private String keyPrefix;

    @Column(nullable = false)
    private String keyHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private AppUser createdBy;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime lastUsedAt;

    /** Nulo = ativa. Preenchida quando revogada. */
    private LocalDateTime revokedAt;

    /** Expiração opcional. Nula = sem expiração. */
    private LocalDateTime expiresAt;

    public boolean isActive() {
        if (revokedAt != null) {
            return false;
        }
        return expiresAt == null || !LocalDateTime.now().isAfter(expiresAt);
    }
}
