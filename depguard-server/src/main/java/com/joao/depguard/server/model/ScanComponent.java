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
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.List;
import java.util.UUID;

/**
 * Componente (dependência) resolvido persistido para um scan.
 * Nome "ScanComponent" (não "Component") para não colidir com
 * {@code org.springframework.stereotype.Component} nem com
 * {@link com.joao.depguard.core.model.Component} (o DTO do core).
 */
@Entity
@Table(name = "scan_components")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    @Column(nullable = false)
    private String ecosystem;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String version;

    @Column(nullable = false)
    private String purl;

    @Column(nullable = false)
    private boolean direct;

    @Column(nullable = false)
    private int depth;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(columnDefinition = "text[]")
    private List<String> licenses;
}
