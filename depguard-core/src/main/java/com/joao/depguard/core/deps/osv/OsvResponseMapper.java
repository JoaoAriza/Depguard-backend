package com.joao.depguard.core.deps.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.depguard.core.model.BumpType;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.util.Fingerprints;
import com.joao.depguard.core.util.SemVer;

import java.util.ArrayList;
import java.util.List;

/**
 * Converte um registro OSV (JSON) + o componente afetado em um {@link VulnFinding}.
 *
 * <p>Função pura, sem rede — totalmente testável com fixtures.
 * EPSS/KEV NÃO são preenchidos aqui (enriquecimento é o Passo 10).
 */
public class OsvResponseMapper {

    public VulnFinding toFinding(JsonNode vuln, Component component) {
        String osvId = text(vuln, "id");
        List<String> aliases = aliases(vuln);
        String cve = aliases.stream()
                .filter(a -> a.startsWith("CVE-"))
                .findFirst()
                .orElse(osvId);

        String fixedVersion = pickFixedVersion(vuln, component);
        String purlNoVersion = component.purl().substring(0, component.purl().lastIndexOf('@'));

        return new VulnFinding(
                Fingerprints.sha256Hex(purlNoVersion + ":" + cve),
                osvId,
                aliases,
                severity(vuln),
                cvssVector(vuln),
                null,                 // epssScore — Passo 10
                false,                // kevListed — Passo 10
                component.purl(),
                fixedVersion,
                SemVer.classifyBump(component.version(), fixedVersion)
        );
    }

    private List<String> aliases(JsonNode vuln) {
        List<String> out = new ArrayList<>();
        for (JsonNode n : array(vuln, "aliases")) {
            out.add(n.asText());
        }
        return out;
    }

    private String cvssVector(JsonNode vuln) {
        for (JsonNode sev : array(vuln, "severity")) {
            String type = text(sev, "type");
            String score = text(sev, "score");
            if (type != null && type.startsWith("CVSS") && score != null) {
                return score;
            }
        }
        return null;
    }

    private Severity severity(JsonNode vuln) {
        String s = severityString(vuln.get("database_specific"));
        if (s == null) {
            for (JsonNode aff : array(vuln, "affected")) {
                s = severityString(aff.get("database_specific"));
                if (s != null) {
                    break;
                }
            }
        }
        return mapSeverity(s);
    }

    private String severityString(JsonNode databaseSpecific) {
        if (databaseSpecific != null && databaseSpecific.hasNonNull("severity")) {
            return databaseSpecific.get("severity").asText();
        }
        return null;
    }

    private Severity mapSeverity(String s) {
        if (s == null) {
            return null;
        }
        return switch (s.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MODERATE", "MEDIUM" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> null;
        };
    }

    /** Menor versão "fixed" estritamente maior que a versão atual, dentre os ranges do pacote. */
    private String pickFixedVersion(JsonNode vuln, Component component) {
        SemVer current = SemVer.parse(component.version());
        String best = null;
        for (JsonNode aff : array(vuln, "affected")) {
            JsonNode pkg = aff.get("package");
            if (pkg == null
                    || !component.ecosystem().equalsIgnoreCase(text(pkg, "ecosystem"))
                    || !component.name().equals(text(pkg, "name"))) {
                continue;
            }
            for (JsonNode range : array(aff, "ranges")) {
                for (JsonNode event : array(range, "events")) {
                    String fixed = text(event, "fixed");
                    if (fixed == null) {
                        continue;
                    }
                    SemVer fv = SemVer.parse(fixed);
                    if (fv.compareTo(current) > 0
                            && (best == null || fv.compareTo(SemVer.parse(best)) < 0)) {
                        best = fixed;
                    }
                }
            }
        }
        return best;
    }

    // --- helpers de leitura de JSON ---------------------------------------

    private static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode n = node.get(field);
        return (n != null && n.isTextual()) ? n.asText() : null;
    }

    private static Iterable<JsonNode> array(JsonNode node, String field) {
        if (node != null) {
            JsonNode n = node.get(field);
            if (n != null && n.isArray()) {
                return n;
            }
        }
        return List.of();
    }
}
