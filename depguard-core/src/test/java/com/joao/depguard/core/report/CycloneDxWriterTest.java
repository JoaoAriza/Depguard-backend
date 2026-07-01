package com.joao.depguard.core.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CycloneDxWriterTest {

    private final CycloneDxWriter writer = new CycloneDxWriter();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void geraSbomCycloneDxComComponenteEVulnerabilidade() throws Exception {
        String json = writer.write(ReportFixtures.sample());
        JsonNode root = mapper.readTree(json);

        assertThat(root.get("bomFormat").asText()).isEqualTo("CycloneDX");
        assertThat(root.get("specVersion").asText()).isEqualTo("1.5");

        JsonNode component = root.get("components").get(0);
        assertThat(component.get("name").asText()).isEqualTo("lodash");
        assertThat(component.get("version").asText()).isEqualTo("4.17.20");
        assertThat(component.get("purl").asText()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(component.get("licenses").get(0).get("license").get("id").asText())
                .isEqualTo("MIT");

        JsonNode vuln = root.get("vulnerabilities").get(0);
        assertThat(vuln.get("id").asText()).isEqualTo("GHSA-35jh-r3h4-6jhm");
        assertThat(vuln.get("source").get("name").asText()).isEqualTo("OSV");
        assertThat(vuln.get("ratings").get(0).get("severity").asText()).isEqualTo("high");
        assertThat(vuln.get("affects").get(0).get("ref").asText())
                .isEqualTo("pkg:npm/lodash@4.17.20");
    }
}
