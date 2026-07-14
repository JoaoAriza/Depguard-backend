package com.joao.depguard.core.model;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Pedido de scan. Imutável; montado pela CLI ou pelo worker do servidor.
 *
 * @param repoRoot              raiz do working tree a escanear
 * @param engines              quais engines rodar
 * @param secretMode           abrangência da varredura de segredos
 * @param allowlist            regras de supressão
 * @param enrichExploitability liga enriquecimento EPSS/KEV (Engine A)
 * @param changedFiles         arquivos alterados, só usado quando {@code secretMode == PR_DIFF}
 */
public record ScanRequest(
        Path repoRoot,
        Set<Engine> engines,
        SecretScanMode secretMode,
        Allowlist allowlist,
        boolean enrichExploitability,
        List<ChangedFile> changedFiles
) {
    /** Compatibilidade: chamadas que não usam PR_DIFF não precisam saber de {@code changedFiles}. */
    public ScanRequest(Path repoRoot, Set<Engine> engines, SecretScanMode secretMode,
                        Allowlist allowlist, boolean enrichExploitability) {
        this(repoRoot, engines, secretMode, allowlist, enrichExploitability, List.of());
    }
}
