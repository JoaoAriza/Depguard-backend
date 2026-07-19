package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.policy.PolicyRules;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Traduz o {@code rules} jsonb (livre, como o §4 do doc o define) para o
 * {@link PolicyRules} tipado do core.
 *
 * <p>Campo AUSENTE herda o default; campo explicitamente {@code null} desliga
 * a regra. A distinção importa: {@code {"failOnSeverity": null}} é "não me
 * bloqueie por severidade", que é diferente de "não opinei" — este último
 * ainda deve pegar o default CRITICAL/HIGH.
 */
@Component
public class PolicyRulesParser {

    public PolicyRules parse(JsonNode node) {
        PolicyRules defaults = PolicyRules.defaults();
        if (node == null || node.isNull() || !node.isObject()) {
            return defaults;
        }

        return new PolicyRules(
                bool(node, "failOnSecrets", defaults.failOnSecrets()),
                severity(node, "failOnSeverity", defaults.failOnSeverity()),
                bool(node, "failOnKev", defaults.failOnKev()),
                epss(node, "failOnEpssAbove", defaults.failOnEpssAbove()),
                licenses(node, "deniedLicenses", defaults.deniedLicenses()));
    }

    private Set<String> licenses(JsonNode node, String field, Set<String> fallback) {
        if (!node.has(field)) {
            return fallback;
        }
        JsonNode v = node.get(field);
        if (v.isNull()) {
            return Set.of();
        }
        if (!v.isArray()) {
            throw badRequest(field + " deve ser uma lista de padrões, ex.: [\"GPL-*\", \"AGPL-*\"].");
        }
        Set<String> out = new LinkedHashSet<>();
        for (JsonNode item : v) {
            if (!item.isTextual() || item.asText().isBlank()) {
                throw badRequest(field + " só aceita padrões de texto não vazios.");
            }
            out.add(item.asText().trim());
        }
        return out;
    }

    private boolean bool(JsonNode node, String field, boolean fallback) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return fallback;
        }
        if (!v.isBoolean()) {
            throw badRequest(field + " deve ser true ou false.");
        }
        return v.asBoolean();
    }

    private Severity severity(JsonNode node, String field, Severity fallback) {
        if (!node.has(field)) {
            return fallback; // ausente: herda o default
        }
        JsonNode v = node.get(field);
        if (v.isNull()) {
            return null; // explícito: regra desligada
        }
        try {
            return Severity.valueOf(v.asText().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw badRequest(field + " inválida: '" + v.asText() + "'. Valores: "
                    + Arrays.stream(Severity.values()).map(Enum::name).collect(Collectors.joining(", ")));
        }
    }

    private Double epss(JsonNode node, String field, Double fallback) {
        if (!node.has(field)) {
            return fallback;
        }
        JsonNode v = node.get(field);
        if (v.isNull()) {
            return null;
        }
        if (!v.isNumber()) {
            throw badRequest(field + " deve ser um número entre 0 e 1.");
        }
        double value = v.asDouble();
        if (value < 0 || value > 1) {
            throw badRequest(field + " deve estar entre 0 e 1 (EPSS é uma probabilidade). Recebido: " + value);
        }
        return value;
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
