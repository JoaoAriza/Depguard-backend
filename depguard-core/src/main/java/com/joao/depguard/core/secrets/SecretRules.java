package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Severity;

import java.util.List;

/**
 * Catálogo de regras por provedor (docs/architecture.md §3.1).
 *
 * <p>Cobertura inicial: os provedores citados no plano do produto. Cada regra
 * é isolada, então adicionar um provedor novo não afeta os demais.
 */
public final class SecretRules {

    private SecretRules() {
    }

    public static List<SecretRule> defaults() {
        return List.of(
                SecretRule.of("DG-SECRET-AWS-ACCESS-KEY",
                        "AKIA[0-9A-Z]{16}", Severity.CRITICAL),
                SecretRule.of("DG-SECRET-GITHUB-TOKEN",
                        "gh[pousr]_[0-9A-Za-z]{36,}", Severity.CRITICAL),
                SecretRule.of("DG-SECRET-STRIPE-LIVE",
                        "sk_live_[0-9A-Za-z]{24,}", Severity.CRITICAL),
                SecretRule.of("DG-SECRET-GOOGLE-API-KEY",
                        "AIza[0-9A-Za-z\\-_]{35}", Severity.HIGH),
                SecretRule.of("DG-SECRET-SLACK-TOKEN",
                        "xox[baprs]-[0-9A-Za-z-]{10,}", Severity.HIGH),
                SecretRule.of("DG-SECRET-PRIVATE-KEY",
                        "-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
                        Severity.CRITICAL),
                SecretRule.of("DG-SECRET-JWT",
                        "eyJ[0-9A-Za-z_-]+\\.[0-9A-Za-z_-]+\\.[0-9A-Za-z_-]+", Severity.MEDIUM)
        );
    }
}
