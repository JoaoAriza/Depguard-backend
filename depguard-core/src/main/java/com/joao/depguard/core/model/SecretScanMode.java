package com.joao.depguard.core.model;

/** Abrangência da varredura de segredos (Engine B). */
public enum SecretScanMode {
    /** Apenas os arquivos do checkout atual. */
    WORKING_TREE,
    /** Percorre o histórico do git (segredo deletado continua no histórico). */
    GIT_HISTORY,
    /** Apenas o diff de um PR (rápido, para o bot). */
    PR_DIFF
}
