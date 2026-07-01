package com.joao.depguard.core.deps.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.BumpType;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.util.Fingerprints;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OsvResponseMapperTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final OsvResponseMapper subject = new OsvResponseMapper();

    private JsonNode fixture(String name) throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/osv/" + name)) {
            return mapper.readTree(in);
        }
    }

    @Test
    void mapeiaVulnDeLodash() throws Exception {
        JsonNode vuln = fixture("lodash-CVE-2021-23337.json");
        Component lodash = new Component(
                "npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", true, 0, List.of("MIT"));

        VulnFinding f = subject.toFinding(vuln, lodash);

        assertThat(f.osvId()).isEqualTo("GHSA-35jh-r3h4-6jhm");
        assertThat(f.aliases()).containsExactly("CVE-2021-23337");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.cvssVector()).startsWith("CVSS:3.1/");
        assertThat(f.affectedPurl()).isEqualTo("pkg:npm/lodash@4.17.20");
        assertThat(f.fixedVersion()).isEqualTo("4.17.21");
        assertThat(f.bumpType()).isEqualTo(BumpType.PATCH);
        assertThat(f.epssScore()).isNull();
        assertThat(f.kevListed()).isFalse();
        assertThat(f.fingerprint())
                .isEqualTo(Fingerprints.sha256Hex("pkg:npm/lodash:CVE-2021-23337"));
    }
}
