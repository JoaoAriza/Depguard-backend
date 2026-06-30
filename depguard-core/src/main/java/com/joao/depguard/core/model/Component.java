package com.joao.depguard.core.model;

import java.util.List;

/**
 * Componente (dependência) resolvido da árvore.
 *
 * @param ecosystem ecossistema OSV (ex.: "npm")
 * @param name      nome do pacote
 * @param version   versão exata resolvida
 * @param purl      Package URL canônico, ex.: {@code pkg:npm/lodash@4.17.20}
 * @param direct    true se dependência direta; false se transitiva
 * @param depth     profundidade na árvore (0 = direta)
 * @param licenses  licenças declaradas
 */
public record Component(
        String ecosystem,
        String name,
        String version,
        String purl,
        boolean direct,
        int depth,
        List<String> licenses
) {}
