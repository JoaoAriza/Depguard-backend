package com.joao.depguard.core.deps.osv;

/** Uma consulta ao OSV: ecossistema + pacote + versão exata. */
public record OsvPackageQuery(String ecosystem, String name, String version) {
}
