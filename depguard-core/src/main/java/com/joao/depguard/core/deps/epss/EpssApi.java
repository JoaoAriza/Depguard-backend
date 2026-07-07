package com.joao.depguard.core.deps.epss;

import java.util.List;
import java.util.Map;

/** Fronteira de rede da EPSS (FIRST.org). Isola o HTTP para testes offline. */
public interface EpssApi {

    /** cve -> score (0..1). CVEs sem score conhecido ficam ausentes do mapa. */
    Map<String, Double> queryBatch(List<String> cveIds);
}
