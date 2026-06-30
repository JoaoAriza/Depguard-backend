package com.joao.depguard.core.model;

import java.util.List;

/**
 * Resultado completo de um scan. Insumo dos emissores SARIF/CycloneDX/JSON.
 *
 * <p>NOTA: o campo {@code cycloneDxBom} (objeto CycloneDX) entra no Passo 4,
 * junto com o {@code CycloneDxWriter} e a dependência cyclonedx-core-java.
 *
 * @param components     árvore de dependências resolvida
 * @param vulnFindings   vulnerabilidades (Engine A)
 * @param secretFindings segredos (Engine B)
 * @param meta           metadados do scan
 */
public record ScanResult(
        List<Component> components,
        List<VulnFinding> vulnFindings,
        List<SecretFinding> secretFindings,
        ScanMeta meta
) {}
