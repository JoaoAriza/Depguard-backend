package com.joao.depguard.core.report;

import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.model.VulnFinding;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.vulnerability.Vulnerability;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Emite CycloneDX 1.5 (SBOM + VEX), consumido pelo monitoramento contínuo e
 * por ferramentas de compliance (docs/architecture.md §6.2). Montado via
 * cyclonedx-core-java — não fazemos hand-roll do formato.
 *
 * <p>LIMITAÇÃO CONHECIDA: licenças são gravadas via {@link License#setId}
 * assumindo identificador SPDX (ex.: MIT, Apache-2.0), que é o formato que o
 * {@code package-lock.json} já usa na prática. Não há validação contra a
 * lista SPDX — licenças não-SPDX ficam como "id" mesmo assim.
 */
public class CycloneDxWriter {

    public String write(ScanResult result) {
        Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        bom.setVersion(1);
        bom.setComponents(components(result));
        bom.setVulnerabilities(vulnerabilities(result));

        try {
            return BomGeneratorFactory.createJson(Version.VERSION_15, bom).toJsonString();
        } catch (GeneratorException e) {
            throw new IllegalStateException("Falha ao gerar SBOM CycloneDX", e);
        }
    }

    private List<org.cyclonedx.model.Component> components(ScanResult result) {
        List<org.cyclonedx.model.Component> out = new ArrayList<>();
        for (com.joao.depguard.core.model.Component c : result.components()) {
            org.cyclonedx.model.Component cdx = new org.cyclonedx.model.Component();
            cdx.setType(org.cyclonedx.model.Component.Type.LIBRARY);
            cdx.setBomRef(c.purl());
            cdx.setName(c.name());
            cdx.setVersion(c.version());
            cdx.setPurl(c.purl());
            if (!c.licenses().isEmpty()) {
                LicenseChoice choice = new LicenseChoice();
                for (String lic : c.licenses()) {
                    License license = new License();
                    license.setId(lic);
                    choice.addLicense(license);
                }
                cdx.setLicenses(choice);
            }
            out.add(cdx);
        }
        return out;
    }

    private List<Vulnerability> vulnerabilities(ScanResult result) {
        List<Vulnerability> out = new ArrayList<>();
        for (VulnFinding vf : result.vulnFindings()) {
            Vulnerability v = new Vulnerability();
            v.setBomRef(vf.fingerprint());
            v.setId(vf.osvId());

            Vulnerability.Source source = new Vulnerability.Source();
            source.setName("OSV");
            v.setSource(source);

            if (vf.severity() != null || vf.cvssVector() != null) {
                Vulnerability.Rating rating = new Vulnerability.Rating();
                if (vf.severity() != null) {
                    rating.setSeverity(mapSeverity(vf.severity()));
                }
                if (vf.cvssVector() != null) {
                    rating.setVector(vf.cvssVector());
                }
                v.addRating(rating);
            }

            Vulnerability.Affect affect = new Vulnerability.Affect();
            affect.setRef(vf.affectedPurl());
            v.setAffects(List.of(affect));

            out.add(v);
        }
        return out;
    }

    private Vulnerability.Rating.Severity mapSeverity(Severity severity) {
        return switch (severity) {
            case CRITICAL -> Vulnerability.Rating.Severity.CRITICAL;
            case HIGH -> Vulnerability.Rating.Severity.HIGH;
            case MEDIUM -> Vulnerability.Rating.Severity.MEDIUM;
            case LOW -> Vulnerability.Rating.Severity.LOW;
            case INFO -> Vulnerability.Rating.Severity.INFO;
        };
    }
}
