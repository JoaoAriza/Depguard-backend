package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Severity;

import java.util.regex.Pattern;

/**
 * Regra de detecção por provedor.
 *
 * @param id        identificador estável da regra (ex.: DG-SECRET-AWS)
 * @param pattern   regex que casa o valor do segredo
 * @param severity  severidade default quando a regra dispara
 */
public record SecretRule(String id, Pattern pattern, Severity severity) {

    public static SecretRule of(String id, String regex, Severity severity) {
        return new SecretRule(id, Pattern.compile(regex), severity);
    }
}
