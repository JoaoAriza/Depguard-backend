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
 * @param verifySecrets        liga verificação ao vivo de segredos (opt-in, §3.3): manda o
 *                             valor cru pro provedor legítimo pra saber se é credencial ativa
 */
public record ScanRequest(
        Path repoRoot,
        Set<Engine> engines,
        SecretScanMode secretMode,
        Allowlist allowlist,
        boolean enrichExploitability,
        List<ChangedFile> changedFiles,
        boolean verifySecrets
) {
    /** Compatibilidade: chamadas que não usam PR_DIFF nem verificação. */
    public ScanRequest(Path repoRoot, Set<Engine> engines, SecretScanMode secretMode,
                        Allowlist allowlist, boolean enrichExploitability) {
        this(repoRoot, engines, secretMode, allowlist, enrichExploitability, List.of(), false);
    }

    /** Compatibilidade: chamadas com {@code changedFiles} mas sem verificação. */
    public ScanRequest(Path repoRoot, Set<Engine> engines, SecretScanMode secretMode,
                        Allowlist allowlist, boolean enrichExploitability, List<ChangedFile> changedFiles) {
        this(repoRoot, engines, secretMode, allowlist, enrichExploitability, changedFiles, false);
    }
}
