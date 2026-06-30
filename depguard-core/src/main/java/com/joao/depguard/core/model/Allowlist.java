package com.joao.depguard.core.model;

import java.util.Set;

/**
 * Regras de supressão (anti-falso-positivo).
 *
 * @param paths         globs de caminhos ignorados
 * @param valueRegexes  regexes de valores ignorados (ex.: placeholders)
 * @param fingerprints  fingerprints específicos já triados como falso-positivo
 */
public record Allowlist(
        Set<String> paths,
        Set<String> valueRegexes,
        Set<String> fingerprints
) {
    public static Allowlist empty() {
        return new Allowlist(Set.of(), Set.of(), Set.of());
    }
}
