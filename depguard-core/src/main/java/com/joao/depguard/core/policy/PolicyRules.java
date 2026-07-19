package com.joao.depguard.core.policy;

import com.joao.depguard.core.model.Severity;

import java.util.Set;

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
 * @param deniedLicenses   licenças de risco, padrões com {@code *} (§2.5); vazio = não avalia
 */
public record PolicyRules(
        boolean failOnSecrets,
        Severity failOnSeverity,
        boolean failOnKev,
        Double failOnEpssAbove,
        Set<String> deniedLicenses
) {

    /**
     * Default de projeto sem policy: exatamente o comportamento que era
     * hardcoded antes deste motor existir (qualquer segredo, ou vuln
     * CRITICAL/HIGH). Mudar isso alteraria silenciosamente o resultado de
     * projetos que nunca configuraram nada.
     *
     * <p>Licenças NÃO entram no default: risco de licença depende de como o
     * projeto se declara (§2.5), então bloquear por isso sem alguém ter
     * pedido quebraria builds por uma regra de compliance que ninguém optou.
     */
    public static PolicyRules defaults() {
        return new PolicyRules(true, Severity.HIGH, false, null, Set.of());
    }
}
