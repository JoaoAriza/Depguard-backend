package com.joao.depguard.core.policy;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Casa identificadores de licença contra padrões simples com {@code *}
 * (ex.: {@code GPL-*}), como o §2.5 do doc descreve.
 *
 * <p><b>Casamento é ANCORADO (a string inteira), não "contém"</b> — de
 * propósito: {@code GPL-*} NÃO pode casar com {@code AGPL-3.0}, que é uma
 * licença diferente. É exatamente por isso que o doc lista {@code GPL-*} e
 * {@code AGPL-*} como dois padrões separados.
 *
 * <p>Expressões SPDX compostas ({@code (MIT OR GPL-3.0)}) são quebradas em
 * termos e qualquer termo que case dispara. Numa expressão OR isso pode
 * super-sinalizar (dá pra cumprir só com MIT), mas é um <i>flag de risco</i>:
 * sinalizar a mais e deixar o humano triar é preferível a deixar passar uma
 * dependência copyleft silenciosamente — e a triagem já existe pra isso.
 */
public final class LicenseMatcher {

    /** Separadores de expressão SPDX: parênteses, OR, AND, WITH e espaços. */
    private static final Pattern SPDX_SEPARATORS = Pattern.compile("[()\\s]+|\\b(?:OR|AND|WITH)\\b");

    private LicenseMatcher() {
    }

    public static boolean isDenied(String license, Set<String> deniedPatterns) {
        if (license == null || license.isBlank() || deniedPatterns.isEmpty()) {
            return false;
        }
        List<String> terms = terms(license);
        for (String pattern : deniedPatterns) {
            Pattern compiled = toRegex(pattern);
            for (String term : terms) {
                if (compiled.matcher(term).matches()) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<String> terms(String license) {
        String normalized = license.toUpperCase(Locale.ROOT).trim();
        List<String> terms = new java.util.ArrayList<>();
        terms.add(normalized); // a string inteira, pro caso de licença simples
        for (String part : SPDX_SEPARATORS.split(normalized)) {
            if (!part.isBlank()) {
                terms.add(part);
            }
        }
        return terms;
    }

    private static Pattern toRegex(String glob) {
        StringBuilder regex = new StringBuilder();
        for (char c : glob.toUpperCase(Locale.ROOT).toCharArray()) {
            if (c == '*') {
                regex.append(".*");
            } else {
                regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(regex.toString());
    }
}
