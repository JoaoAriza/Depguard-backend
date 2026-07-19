package com.joao.depguard.core.policy;

import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VerificationStatus;
import com.joao.depguard.core.model.VulnFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyEvaluatorTest {

    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    @Test
    void semAchadosNaoBloqueia() {
        PolicyDecision d = evaluator.evaluate(PolicyRules.defaults(), List.of(), List.of());

        assertThat(d.blocking()).isFalse();
        assertThat(d.reasons()).isEmpty();
    }

    @Test
    void failOnSecretsBloqueiaComQualquerSegredo() {
        PolicyDecision d = evaluator.evaluate(PolicyRules.defaults(), List.of(), List.of(secret()));

        assertThat(d.blocking()).isTrue();
        assertThat(d.reasons()).singleElement().asString().contains("1 segredo(s)");
    }

    @Test
    void failOnSecretsDesligadoIgnoraSegredos() {
        PolicyRules rules = new PolicyRules(false, null, false, null);

        assertThat(evaluator.evaluate(rules, List.of(), List.of(secret())).blocking()).isFalse();
    }

    @Test
    void failOnSeverityBloqueiaSeveridadeIgualOuAcima() {
        PolicyRules rules = new PolicyRules(false, Severity.HIGH, false, null);

        assertThat(evaluator.evaluate(rules, List.of(vuln(Severity.CRITICAL)), List.of()).blocking()).isTrue();
        assertThat(evaluator.evaluate(rules, List.of(vuln(Severity.HIGH)), List.of()).blocking()).isTrue();
        assertThat(evaluator.evaluate(rules, List.of(vuln(Severity.MEDIUM)), List.of()).blocking()).isFalse();
        assertThat(evaluator.evaluate(rules, List.of(vuln(Severity.LOW)), List.of()).blocking()).isFalse();
    }

    @Test
    void failOnSeverityNuloNaoAvaliaPorSeveridade() {
        PolicyRules rules = new PolicyRules(false, null, false, null);

        assertThat(evaluator.evaluate(rules, List.of(vuln(Severity.CRITICAL)), List.of()).blocking()).isFalse();
    }

    @Test
    void failOnKevBloqueiaSoQuandoListadoNoKev() {
        PolicyRules rules = new PolicyRules(false, null, true, null);

        assertThat(evaluator.evaluate(rules, List.of(vulnKev(true)), List.of()).blocking()).isTrue();
        assertThat(evaluator.evaluate(rules, List.of(vulnKev(false)), List.of()).blocking()).isFalse();
    }

    @Test
    void failOnEpssAboveComparaComOLimiar() {
        PolicyRules rules = new PolicyRules(false, null, false, 0.5);

        assertThat(evaluator.evaluate(rules, List.of(vulnEpss(0.9)), List.of()).blocking()).isTrue();
        assertThat(evaluator.evaluate(rules, List.of(vulnEpss(0.1)), List.of()).blocking()).isFalse();
        // exatamente no limiar não bloqueia (regra é "acima de")
        assertThat(evaluator.evaluate(rules, List.of(vulnEpss(0.5)), List.of()).blocking()).isFalse();
    }

    @Test
    void vulnSemEpssNaoBloqueiaPorEpss() {
        PolicyRules rules = new PolicyRules(false, null, false, 0.5);

        assertThat(evaluator.evaluate(rules, List.of(vulnEpss(null)), List.of()).blocking()).isFalse();
    }

    /** Formatação de número não pode depender do locale da JVM (pt-BR usa vírgula). */
    @Test
    void motivoDeEpssUsaPontoComoSeparadorDecimal() {
        PolicyRules rules = new PolicyRules(false, null, false, 0.5);

        PolicyDecision d = evaluator.evaluate(rules, List.of(vulnEpss(0.9)), List.of());

        assertThat(d.reasons()).singleElement().asString().contains("0.50").doesNotContain("0,50");
    }

    @Test
    void acumulaTodosOsMotivosQuandoVariasRegrasDisparam() {
        PolicyRules rules = new PolicyRules(true, Severity.HIGH, true, 0.5);

        PolicyDecision d = evaluator.evaluate(
                rules, List.of(vulnAll(Severity.CRITICAL, true, 0.9)), List.of(secret()));

        assertThat(d.blocking()).isTrue();
        assertThat(d.reasons()).hasSize(4); // segredo + severidade + KEV + EPSS
    }

    /** O default tem que reproduzir o bloqueio que era hardcoded antes do motor. */
    @Test
    void defaultReproduzOComportamentoHardcodedAnterior() {
        PolicyRules defaults = PolicyRules.defaults();

        // qualquer segredo bloqueia
        assertThat(evaluator.evaluate(defaults, List.of(), List.of(secret())).blocking()).isTrue();
        // CRITICAL/HIGH bloqueiam
        assertThat(evaluator.evaluate(defaults, List.of(vuln(Severity.CRITICAL)), List.of()).blocking()).isTrue();
        assertThat(evaluator.evaluate(defaults, List.of(vuln(Severity.HIGH)), List.of()).blocking()).isTrue();
        // MEDIUM pra baixo não
        assertThat(evaluator.evaluate(defaults, List.of(vuln(Severity.MEDIUM)), List.of()).blocking()).isFalse();
        // KEV/EPSS não entravam no hardcoded
        assertThat(evaluator.evaluate(defaults, List.of(vulnAll(Severity.LOW, true, 0.99)), List.of()).blocking())
                .isFalse();
    }

    private SecretFinding secret() {
        return new SecretFinding("fp", "DG-SECRET-AWS-ACCESS-KEY", "a.env", 1, 1, null,
                "AKIA…MNOP", "hash", 4.2, VerificationStatus.NOT_CHECKED, false);
    }

    private VulnFinding vuln(Severity severity) {
        return vulnAll(severity, false, null);
    }

    private VulnFinding vulnKev(boolean kev) {
        return vulnAll(Severity.LOW, kev, null);
    }

    private VulnFinding vulnEpss(Double epss) {
        return vulnAll(Severity.LOW, false, epss);
    }

    private VulnFinding vulnAll(Severity severity, boolean kev, Double epss) {
        return new VulnFinding("fp", "GHSA-x", List.of("CVE-2021-1"), severity, null,
                epss, kev, "pkg:npm/lodash@4.17.20", "4.17.21", null);
    }
}
