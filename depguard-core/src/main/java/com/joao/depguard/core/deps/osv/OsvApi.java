package com.joao.depguard.core.deps.osv;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * Fronteira de rede do OSV. Isola o HTTP para que a orquestração
 * ({@link OsvVulnerabilityScanner}) seja testável offline com um fake.
 */
public interface OsvApi {

    /**
     * Consulta em lote. Para cada query, na mesma ordem, devolve os IDs de
     * vulnerabilidade encontrados (lista vazia quando não há).
     */
    List<List<String>> queryBatch(List<OsvPackageQuery> queries);

    /** Registro OSV completo de um ID (ou {@code null} se não encontrado). */
    JsonNode getVuln(String id);
}
