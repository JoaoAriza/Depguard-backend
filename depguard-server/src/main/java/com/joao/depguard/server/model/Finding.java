package com.joao.depguard.server.model;

import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

/**
 * Finding unificado (vulnerabilidade de dependência OU segredo). O tipo e a
 * severidade reaproveitam os enums do core ({@link FindingType},
 * {@link Severity}) em vez de duplicá-los aqui.
 */
@Entity
@Table(name = "findings", indexes = @Index(columnList = "fingerprint"))
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingType type;

    /** Identidade estável entre scans (docs/architecture.md §4.1) — não confundir com {@code id}. */
    @Column(nullable = false)
    private String fingerprint;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    /** Payload específico do tipo (campos de VulnFinding ou SecretFinding) — JSON opaco no MVP. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", nullable = false)
    private String detail;
}
