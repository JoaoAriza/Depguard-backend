package com.joao.depguard.core.policy;

import com.joao.depguard.core.model.Severity;

/**
 * Condições de fail de um projeto (docs/architecture.md §5, coluna
 * {@code policy.rules}). Campos nulos = regra desligada, não "valor zero" —
 * é o que permite uma policy parcial ({@code {"failOnKev": true}}) sem herdar
 * silenciosamente um limiar que ninguém pediu.
 *
 * @param failOnSecrets    qualquer segredo bloqueia
 * @param failOnSeverity   bloqueia vuln com severidade >= esta (null = não avalia)
 * @param failOnKev        bloqueia vuln no catálogo CISA KEV (§2.4)
 * @param failOnEpssAbove  bloqueia vuln com EPSS acima deste valor 0..1 (null = não avalia)
 */
public record PolicyRules(
        boolean failOnSecrets,
        Severity failOnSeverity,
        boolean failOnKev,
        Double failOnEpssAbove
) {

    /**
     * Default de projeto sem policy: exatamente o comportamento que era
     * hardcoded antes deste motor existir (qualquer segredo, ou vuln
     * CRITICAL/HIGH). Mudar isso alteraria silenciosamente o resultado de
     * projetos que nunca configuraram nada.
     */
    public static PolicyRules defaults() {
        return new PolicyRules(true, Severity.HIGH, false, null);
    }
}
