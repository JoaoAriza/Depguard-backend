package com.joao.depguard.core.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JsonReportWriterTest {

    private final JsonReportWriter writer = new JsonReportWriter();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void serializaScanResultCompleto() throws Exception {
        String json = writer.write(ReportFixtures.sample());
        JsonNode root = mapper.readTree(json);

        assertThat(root.get("components")).hasSize(1);
        assertThat(root.get("components").get(0).get("purl").asText())
                .isEqualTo("pkg:npm/lodash@4.17.20");

        assertThat(root.get("vulnFindings")).hasSize(1);
        assertThat(root.get("vulnFindings").get(0).get("osvId").asText())
                .isEqualTo("GHSA-35jh-r3h4-6jhm");

        assertThat(root.get("secretFindings")).hasSize(1);
        assertThat(root.get("secretFindings").get(0).get("maskedSample").asText())
                .isEqualTo("AKIA…MNOP");

        assertThat(root.get("meta").get("partial").asBoolean()).isFalse();
        // nunca guarda o valor cru
        assertThat(json).doesNotContain("AKIAABCDEFGHIJKLMNOP");
    }
}
