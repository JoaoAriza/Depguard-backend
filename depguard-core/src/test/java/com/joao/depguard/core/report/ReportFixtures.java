package com.joao.depguard.core.report;

import com.joao.depguard.core.model.BumpType;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.ScanMeta;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VerificationStatus;
import com.joao.depguard.core.model.VulnFinding;

import java.util.List;
import java.util.Set;

/** Fixtures compartilhadas entre os testes de emissores. */
final class ReportFixtures {

    private ReportFixtures() {
    }

    static ScanResult sample() {
        Component lodash = new Component(
                "npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", true, 0, List.of("MIT"));

        VulnFinding vuln = new VulnFinding(
                "vuln-fingerprint-abc",
                "GHSA-35jh-r3h4-6jhm",
                List.of("CVE-2021-23337"),
                Severity.HIGH,
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                null,
                false,
                "pkg:npm/lodash@4.17.20",
                "4.17.21",
                BumpType.PATCH
        );

        SecretFinding secret = new SecretFinding(
                "secret-fingerprint-xyz",
                "DG-SECRET-AWS-ACCESS-KEY",
                "config/app.env",
                3,
                3,
                null,
                "AKIA…MNOP",
                "deadbeef",
                4.2,
                VerificationStatus.NOT_CHECKED,
                false
        );

        ScanMeta meta = new ScanMeta(false, Set.of("npm"), 42L);

        return new ScanResult(List.of(lodash), List.of(vuln), List.of(secret), meta);
    }
}
