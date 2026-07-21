package com.joao.depguard.core.model;

import java.util.LinkedHashSet;
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

    /**
     * União com outra allowlist (ex.: a do {@code .depguard.yml} do repo com a
     * da triagem do servidor). União porque as duas SUPRIMEM — juntar amplia a
     * supressão, o que é o comportamento esperado quando há as duas fontes.
     */
    public Allowlist merge(Allowlist other) {
        return new Allowlist(
                union(paths, other.paths),
                union(valueRegexes, other.valueRegexes),
                union(fingerprints, other.fingerprints));
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> out = new LinkedHashSet<>(a);
        out.addAll(b);
        return out;
    }
}
