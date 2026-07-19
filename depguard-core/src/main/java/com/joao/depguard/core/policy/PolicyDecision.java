package com.joao.depguard.core.policy;

import java.util.List;

/**
 * Resultado da avaliação de uma policy.
 *
 * <p>Carrega os MOTIVOS, não só o booleano: quem tem o merge bloqueado
 * precisa saber qual regra disparou pra poder agir (o Check Run mostra isso
 * direto no PR).
 *
 * @param blocking true se alguma regra disparou
 * @param reasons  motivos legíveis, um por regra disparada; vazio se não bloqueia
 */
public record PolicyDecision(boolean blocking, List<String> reasons) {

    public static PolicyDecision pass() {
        return new PolicyDecision(false, List.of());
    }
}
