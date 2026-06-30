package com.joao.depguard.core.model;

/** Resultado da verificação ao vivo de um segredo (Engine B, Fase 2). */
public enum VerificationStatus {
    /** Credencial confirmada como ativa. */
    VERIFIED,
    /** Verificada e inativa/inválida. */
    UNVERIFIED,
    /** Verificação não executada (opt-in desligado). */
    NOT_CHECKED
}
