package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.ScanMeta;
import com.joao.depguard.core.model.ScanResult;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.report.SarifWriter;
import com.joao.depguard.server.model.Finding;
import com.joao.depguard.server.model.Sbom;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.repository.FindingRepository;
import com.joao.depguard.server.repository.SbomRepository;
import com.joao.depguard.server.repository.ScanComponentRepository;
import com.joao.depguard.server.repository.ScanRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Reconstrói um {@code ScanResult} do core a partir das linhas persistidas
 * (Scan/ScanComponent/Finding) para reaproveitar o {@code SarifWriter} do
 * core. SARIF nunca é guardado como um blob separado — é sempre derivado do
 * que está no banco, então não há como divergir.
 */
@Service
public class ScanExportService {

    private final ScanRepository scanRepository;
    private final ScanComponentRepository scanComponentRepository;
    private final FindingRepository findingRepository;
    private final SbomRepository sbomRepository;
    private final ObjectMapper mapper;
    private final SarifWriter sarifWriter = new SarifWriter();

    public ScanExportService(ScanRepository scanRepository,
                              ScanComponentRepository scanComponentRepository,
                              FindingRepository findingRepository,
                              SbomRepository sbomRepository,
                              ObjectMapper mapper) {
        this.scanRepository = scanRepository;
        this.scanComponentRepository = scanComponentRepository;
        this.findingRepository = findingRepository;
        this.sbomRepository = sbomRepository;
        this.mapper = mapper;
    }

    /** SBOM salvo verbatim no scan (não regenerado — ver Passo 6d). */
    public String sbom(UUID scanId) {
        Scan scan = getScanOrThrow(scanId);
        return sbomRepository.findByScan(scan)
                .map(Sbom::getDocument)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "SBOM ainda não disponível (scan não concluído ou sem dependências)."));
    }

    public String sarif(UUID scanId) {
        Scan scan = getScanOrThrow(scanId);
        return sarifWriter.write(reconstruct(scan));
    }

    ScanResult reconstruct(Scan scan) {
        List<Component> components = scanComponentRepository.findByScan(scan).stream()
                .map(c -> new Component(c.getEcosystem(), c.getName(), c.getVersion(), c.getPurl(),
                        c.isDirect(), c.getDepth(), c.getLicenses()))
                .toList();

        List<VulnFinding> vulnFindings = new ArrayList<>();
        List<SecretFinding> secretFindings = new ArrayList<>();
        for (Finding f : findingRepository.findByScan(scan)) {
            if (f.getType() == FindingType.DEPENDENCY_VULN) {
                vulnFindings.add(readJson(f.getDetail(), VulnFinding.class));
            } else {
                secretFindings.add(readJson(f.getDetail(), SecretFinding.class));
            }
        }

        ScanMeta meta = new ScanMeta(scan.isPartial(), Set.of(), 0);
        return new ScanResult(components, vulnFindings, secretFindings, meta);
    }

    private Scan getScanOrThrow(UUID scanId) {
        return scanRepository.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan não encontrado."));
    }

    private <T> T readJson(String json, Class<T> type) {
        try {
            return mapper.readValue(json, type);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao desserializar finding persistido", e);
        }
    }
}
