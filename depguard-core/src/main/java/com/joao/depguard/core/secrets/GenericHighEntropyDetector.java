package com.joao.depguard.core.secrets;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detecta segredos genéricos (sem padrão de provedor) por entropia alta,
 * exigindo que o valor esteja atribuído a uma chave que pareça credencial
 * (docs/architecture.md §3.1: "só dispara em strings que parecem credencial").
 */
public class GenericHighEntropyDetector {

    /** ex.: token = "...", secret: '...', API_KEY="..." */
    private static final Pattern ASSIGNMENT = Pattern.compile(
            "(?i)(?:token|secret|api[_-]?key|password|passwd|access[_-]?key)\\s*[:=]\\s*['\"]([A-Za-z0-9+/_=\\-]{20,})['\"]");

    private static final double MIN_ENTROPY = 3.5;
    private static final int MIN_LENGTH = 20;

    public List<MatchCandidate> find(String line) {
        List<MatchCandidate> out = new ArrayList<>();
        Matcher m = ASSIGNMENT.matcher(line);
        while (m.find()) {
            String value = m.group(1);
            if (value.length() >= MIN_LENGTH && ShannonEntropy.of(value) >= MIN_ENTROPY) {
                out.add(new MatchCandidate(value, m.start(1), m.end(1)));
            }
        }
        return out;
    }

    public record MatchCandidate(String value, int start, int end) {
    }
}
