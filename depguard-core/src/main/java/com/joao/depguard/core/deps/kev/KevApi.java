package com.joao.depguard.core.deps.kev;

import java.util.Set;

/** Fronteira de rede do catálogo CISA KEV. Isola o HTTP para testes offline. */
public interface KevApi {

    /** Todo o catálogo, como conjunto de CVE IDs. Cacheado pelo caller. */
    Set<String> fetchAllCveIds();
}
