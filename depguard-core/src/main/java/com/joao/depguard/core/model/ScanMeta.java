package com.joao.depguard.core.model;

import java.util.Set;

/**
 * Metadados do scan.
 *
 * @param partial         true se o resultado é incompleto (ex.: sem lockfile)
 * @param ecosystems      ecossistemas detectados
 * @param durationMillis  duração total
 */
public record ScanMeta(
        boolean partial,
        Set<String> ecosystems,
        long durationMillis
) {}
