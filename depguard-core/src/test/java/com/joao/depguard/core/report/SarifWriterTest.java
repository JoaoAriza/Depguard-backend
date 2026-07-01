package com.joao.depguard.core.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SarifWriterTest {

    private final SarifWriter writer = new SarifWriter();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void geraSarifValidoComAmbosOsTipos() throws Exception {
        String sarif = writer.write(ReportFixtures.sample());
        JsonNode root = mapper.readTree(sarif);

        assertThat(root.get("version").asText()).isEqualTo("2.1.0");
        JsonNode run = root.get("runs").get(0);
        assertThat(run.get("tool").get("driver").get("name").asText()).isEqualTo("DepGuard");

        JsonNode rules = run.get("tool").get("driver").get("rules");
        assertThat(rules).isNotEmpty();
        assertThat(anyRuleId(rules, "DG-VULN")).isTrue();
        assertThat(anyRuleId(rules, "DG-SECRET-AWS-ACCESS-KEY")).isTrue();

        JsonNode results = run.get("results");
        assertThat(results).hasSize(2);

        JsonNode vulnResult = findByRuleId(results, "DG-VULN");
        assertThat(vulnResult.get("level").asText()).isEqualTo("error");
        assertThat(vulnResult.get("message").get("text").asText()).contains("lodash");
        assertThat(vulnResult.get("partialFingerprints").get("depguard").asText())
                .isEqualTo("vuln-fingerprint-abc");

        JsonNode secretResult = findByRuleId(results, "DG-SECRET-AWS-ACCESS-KEY");
        assertThat(secretResult.get("locations").get(0)
                .get("physicalLocation").get("artifactLocation").get("uri").asText())
                .isEqualTo("config/app.env");
        assertThat(secretResult.get("locations").get(0)
                .get("physicalLocation").get("region").get("startLine").asInt())
                .isEqualTo(3);
        assertThat(secretResult.get("message").get("text").asText())
                .contains("AKIA…MNOP")
                .doesNotContain("AKIAABCDEFGHIJKLMNOP");
        assertThat(secretResult.get("partialFingerprints").get("depguard").asText())
                .isEqualTo("secret-fingerprint-xyz");
    }

    private boolean anyRuleId(JsonNode rules, String id) {
        for (JsonNode r : rules) {
            if (r.get("id").asText().equals(id)) {
                return true;
            }
        }
        return false;
    }

    private JsonNode findByRuleId(JsonNode results, String ruleId) {
        for (JsonNode r : results) {
            if (r.get("ruleId").asText().equals(ruleId)) {
                return r;
            }
        }
        throw new AssertionError("nenhum resultado com ruleId=" + ruleId);
    }
}
