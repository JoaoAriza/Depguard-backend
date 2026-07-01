package com.joao.depguard.server.model;

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

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Triagem de um finding, chaveada por {@code (project, fingerprint)} — NÃO
 * por {@code finding.id} — para que um re-scan não apague a triagem já feita
 * (docs/architecture.md §4.1, análogo ao {@code ScanChangeDetector} do
 * CyberAudit).
 */
@Entity
@Table(name = "finding_triages",
        uniqueConstraints = @UniqueConstraint(columnNames = {"project_id", "fingerprint"}))
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FindingTriage {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    @Column(nullable = false)
    private String fingerprint;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TriageStatus status;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assignee_id")
    private AppUser assignee;

    @Column(length = 2000)
    private String note;

    @Column(nullable = false)
    private LocalDateTime updatedAt;
}
