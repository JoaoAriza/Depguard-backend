package com.joao.depguard.core.model;

import java.util.List;

/**
 * Vulnerabilidade encontrada em um componente (Engine A).
 *
 * @param fingerprint  identidade estável entre scans (ver docs/architecture.md §4.1)
 * @param osvId        ID OSV (ex.: GHSA-...)
 * @param aliases      CVEs e outros aliases
 * @param severity     severidade normalizada
 * @param cvssVector   vetor CVSS, quando disponível
 * @param epssScore    probabilidade EPSS (0..1), null se não enriquecido
 * @param kevListed    true se consta no catálogo CISA KEV
 * @param affectedPurl purl do componente afetado
 * @param fixedVersion menor versão segura, null se não houver correção
 * @param bumpType     tipo do salto até a versão segura
 */
public record VulnFinding(
        String fingerprint,
        String osvId,
        List<String> aliases,
        Severity severity,
        String cvssVector,
        Double epssScore,
        boolean kevListed,
        String affectedPurl,
        String fixedVersion,
        BumpType bumpType
) {}
