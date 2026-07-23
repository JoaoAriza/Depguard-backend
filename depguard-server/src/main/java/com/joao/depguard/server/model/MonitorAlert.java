package com.joao.depguard.server.model;

import com.joao.depguard.core.model.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Alerta do monitoramento contínuo (docs/architecture.md §7): uma
 * vulnerabilidade que o OSV passou a conhecer numa dependência que o projeto
 * <b>já shipou</b> — inédita em relação ao último scan concluído (baseline).
 *
 * <p>Identidade por {@code (project, fingerprint)} — igual à {@link FindingTriage}
 * (§4.1) — para que a linha seja a identidade estável daquela dupla dep+CVE e
 * alterne {@link MonitorAlertStatus#OPEN}/{@link MonitorAlertStatus#RESOLVED} ao
 * longo do tempo, em vez de acumular duplicatas a cada re-check diário. É o que
 * dá a idempotência do job (não re-alerta o mesmo CVE toda noite) e trata o
 * caso "dep voltou a ser vulnerável" reabrindo a mesma linha.
 *
 * <p>Tabela nova: o CHECK constraint do enum {@code status} nasce correto na
 * criação (a pegadinha do {@code ddl-auto} só morde ao ADICIONAR valor a um
 * enum de tabela já existente — docs §4).
 */
@Entity
@Table(name = "monitor_alerts",
        uniqueConstraints = @UniqueConstraint(columnNames = {"project_id", "fingerprint"}))
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MonitorAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    /** Mesma identidade estável dos findings/triagem (§4.1): {@code sha256(purl_sem_versão + ":" + cve)}. */
    @Column(nullable = false)
    private String fingerprint;

    @Column(nullable = false)
    private String osvId;

    /** CVE principal (primeiro alias {@code CVE-}), null se o registro é GHSA-only. */
    private String cve;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(nullable = false)
    private String affectedPurl;

    /** Menor versão segura, null se não houver correção. */
    private String fixedVersion;

    /** Probabilidade de exploração (EPSS 0..1), null se não enriquecido. */
    private Double epssScore;

    @Column(nullable = false)
    private boolean kevListed;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private MonitorAlertStatus status;

    /** Payload completo do {@code VulnFinding} — mesma abordagem opaca dos {@link Finding}. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", nullable = false)
    private String detail;

    @Column(nullable = false)
    private LocalDateTime detectedAt;

    private LocalDateTime resolvedAt;
}
