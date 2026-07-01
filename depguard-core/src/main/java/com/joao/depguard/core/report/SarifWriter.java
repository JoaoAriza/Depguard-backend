package com.joao.depguard.core.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.secrets.SecretRule;
import com.joao.depguard.core.secrets.SecretRules;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Emite SARIF 2.1.0 (docs/architecture.md §6.1), consumido pelo
 * "Code scanning" do GitHub. {@code partialFingerprints.depguard} carrega o
 * fingerprint estável de cada finding para o GitHub deduplicar entre scans.
 *
 * <p>LIMITAÇÃO CONHECIDA: {@link com.joao.depguard.core.model.Component} ainda
 * não rastreia o caminho do manifesto de origem, então achados de dependência
 * apontam para {@code package-lock.json} linha 1 (convenção, não a linha real
 * da árvore). Achados de segredo já usam caminho/linha reais.
 */
public class SarifWriter {

    private static final String RULE_VULN_ID = "DG-VULN";
    private static final Map<String, RuleMeta> RULE_CATALOG = buildRuleCatalog();

    private final ObjectMapper mapper;

    public SarifWriter() {
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    public String write(ScanResult result) {
        ObjectNode root = mapper.createObjectNode();
        root.put("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.put("version", "2.1.0");

        ObjectNode run = root.putArray("runs").addObject();
        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "DepGuard");
        ArrayNode rulesNode = driver.putArray("rules");
        for (RuleMeta rule : RULE_CATALOG.values()) {
            ObjectNode ruleNode = rulesNode.addObject();
            ruleNode.put("id", rule.id());
            ruleNode.put("name", rule.name());
            ruleNode.putObject("shortDescription").put("text", rule.shortDescription());
        }

        ArrayNode results = run.putArray("results");
        for (VulnFinding f : result.vulnFindings()) {
            results.add(vulnResult(f));
        }
        for (SecretFinding f : result.secretFindings()) {
            results.add(secretResult(f));
        }

        return root.toPrettyString();
    }

    private ObjectNode vulnResult(VulnFinding f) {
        ObjectNode node = mapper.createObjectNode();
        node.put("ruleId", RULE_VULN_ID);
        node.put("level", levelFor(f.severity()));

        String id = f.aliases().isEmpty() ? f.osvId() : f.aliases().get(0);
        String fix = f.fixedVersion() != null
                ? " — corrigido em " + f.fixedVersion()
                : " — sem correção conhecida";
        node.putObject("message").put("text",
                "Dependência vulnerável: " + f.affectedPurl() + " — " + id + fix);

        ArrayNode locations = node.putArray("locations");
        ObjectNode location = locations.addObject().putObject("physicalLocation");
        location.putObject("artifactLocation").put("uri", "package-lock.json");
        location.putObject("region").put("startLine", 1);

        node.putObject("partialFingerprints").put("depguard", f.fingerprint());
        return node;
    }

    private ObjectNode secretResult(SecretFinding f) {
        ObjectNode node = mapper.createObjectNode();
        node.put("ruleId", f.ruleId());
        RuleMeta meta = RULE_CATALOG.get(f.ruleId());
        node.put("level", meta != null ? meta.defaultLevel() : "warning");
        node.putObject("message").put("text",
                "Segredo detectado (" + f.ruleId() + "): " + f.maskedSample());

        ArrayNode locations = node.putArray("locations");
        ObjectNode location = locations.addObject().putObject("physicalLocation");
        location.putObject("artifactLocation").put("uri", f.path());
        location.putObject("region").put("startLine", f.lineStart());

        node.putObject("partialFingerprints").put("depguard", f.fingerprint());
        return node;
    }

    private static Map<String, RuleMeta> buildRuleCatalog() {
        Map<String, RuleMeta> catalog = new LinkedHashMap<>();
        catalog.put(RULE_VULN_ID, new RuleMeta(RULE_VULN_ID, "VulnerableDependency",
                "Dependência com vulnerabilidade conhecida (OSV).", "error"));

        for (SecretRule rule : SecretRules.defaults()) {
            String name = friendlyName(rule.id());
            catalog.put(rule.id(), new RuleMeta(rule.id(), name,
                    "Segredo detectado: " + name + ".", levelFor(rule.severity())));
        }
        catalog.put("DG-SECRET-GENERIC-HIGH-ENTROPY", new RuleMeta(
                "DG-SECRET-GENERIC-HIGH-ENTROPY", "GenericHighEntropySecret",
                "Valor de alta entropia atribuído a uma chave que parece credencial.",
                "warning"));
        return catalog;
    }

    private static String friendlyName(String ruleId) {
        String stripped = ruleId.replaceFirst("^DG-SECRET-", "");
        StringBuilder sb = new StringBuilder();
        for (String part : stripped.split("-")) {
            if (!part.isEmpty()) {
                sb.append(Character.toUpperCase(part.charAt(0)))
                        .append(part.substring(1).toLowerCase());
            }
        }
        return sb.toString();
    }

    private static String levelFor(Severity severity) {
        if (severity == null) {
            return "warning";
        }
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private record RuleMeta(String id, String name, String shortDescription, String defaultLevel) {
    }
}
