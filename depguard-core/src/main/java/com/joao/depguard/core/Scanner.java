package com.joao.depguard.core;

import com.joao.depguard.core.model.ScanRequest;
import com.joao.depguard.core.model.ScanResult;

/**
 * Ponto de entrada único do scanner core.
 *
 * <p>Implementações são offline, exceto as chamadas a OSV/EPSS/KEV feitas
 * pela Engine de dependências. Esta interface é o contrato compartilhado
 * entre a CLI ({@code depguard-cli}) e o backend ({@code depguard-server}).
 */
public interface Scanner {

    ScanResult scan(ScanRequest request);
}
