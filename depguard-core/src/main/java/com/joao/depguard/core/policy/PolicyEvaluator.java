package com.joao.depguard.core.policy;

import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VulnFinding;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Avalia as condições de fail de um projeto contra o resultado de um scan
 * (docs/architecture.md §5). Lógica pura: não sabe de HTTP, banco nem triagem
 * — quem chama já entrega só os findings que devem contar (o servidor filtra
 * os triados como FALSE_POSITIVE/ACCEPTED_RISK antes).
 */
public class PolicyEvaluator {

    public PolicyDecision evaluate(PolicyRules rules, List<VulnFinding> vulnFindings,
                                    List<SecretFinding> secretFindings) {
        List<String> reasons = new ArrayList<>();

        if (rules.failOnSecrets() && !secretFindings.isEmpty()) {
            reasons.add(secretFindings.size() + " segredo(s) encontrado(s)");
        }

        if (rules.failOnSeverity() != null) {
            long n = vulnFindings.stream()
                    .filter(v -> v.severity() != null && atLeastAsSevere(v.severity(), rules.failOnSeverity()))
                    .count();
            if (n > 0) {
                reasons.add(n + " vulnerabilidade(s) com severidade " + rules.failOnSeverity() + " ou acima");
            }
        }

        if (rules.failOnKev()) {
            long n = vulnFindings.stream().filter(VulnFinding::kevListed).count();
            if (n > 0) {
                reasons.add(n + " vulnerabilidade(s) no catálogo CISA KEV (exploração conhecida)");
            }
        }

        if (rules.failOnEpssAbove() != null) {
            long n = vulnFindings.stream()
                    .filter(v -> v.epssScore() != null && v.epssScore() > rules.failOnEpssAbove())
                    .count();
            if (n > 0) {
                // Locale.ROOT: sem isso o separador decimal vira vírgula em
                // pt-BR e o texto sai "EPSS acima de 0,5".
                reasons.add(String.format(Locale.ROOT, "%d vulnerabilidade(s) com EPSS acima de %.2f",
                        n, rules.failOnEpssAbove()));
            }
        }

        return reasons.isEmpty() ? PolicyDecision.pass() : new PolicyDecision(true, reasons);
    }

    /**
     * O enum {@link Severity} é declarado do mais grave pro menos grave, então
     * "pelo menos tão grave quanto" é ordinal MENOR ou igual.
     */
    private boolean atLeastAsSevere(Severity actual, Severity threshold) {
        return actual.ordinal() <= threshold.ordinal();
    }
}
