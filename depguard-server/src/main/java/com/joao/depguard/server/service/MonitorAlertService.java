package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.server.model.Finding;
import com.joao.depguard.server.model.FindingTriage;
import com.joao.depguard.server.model.MonitorAlert;
import com.joao.depguard.server.model.MonitorAlertStatus;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.TriageStatus;
import com.joao.depguard.server.repository.FindingRepository;
import com.joao.depguard.server.repository.FindingTriageRepository;
import com.joao.depguard.server.repository.MonitorAlertRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Detecção de "CVE novo vs. estado anterior" (docs/architecture.md §7, 3b) e
 * persistência dos {@link MonitorAlert}. Bean SEPARADO do {@link MonitorService}
 * de propósito: o {@code @Transactional} desta reconciliação só funciona através
 * do proxy do Spring — se {@link MonitorService} (que faz o I/O de rede do
 * re-check) chamasse um método {@code @Transactional} próprio (self-invocation),
 * ele rodaria sem transação, silenciosamente. Mesmo motivo do
 * {@code ScanExecutionService} ser separado do {@code ScanService}.
 */
@Service
public class MonitorAlertService {

    /** Triagem que suprime alerta — não faz sentido alertar sobre o que já foi descartado (§3c). */
    private static final Set<TriageStatus> SUPPRESSED =
            EnumSet.of(TriageStatus.FALSE_POSITIVE, TriageStatus.ACCEPTED_RISK);

    private final MonitorAlertRepository alertRepository;
    private final FindingRepository findingRepository;
    private final FindingTriageRepository triageRepository;
    private final ObjectMapper mapper = new ObjectMapper();

    public MonitorAlertService(MonitorAlertRepository alertRepository,
                               FindingRepository findingRepository,
                               FindingTriageRepository triageRepository) {
        this.alertRepository = alertRepository;
        this.findingRepository = findingRepository;
        this.triageRepository = triageRepository;
    }

    /** Alertas novos/reabertos nesta execução + quantos foram resolvidos. */
    public record ReconcileResult(List<MonitorAlert> newlyAlerted, int resolvedCount) {}

    /**
     * Reconcilia os alertas do projeto com o resultado do re-check.
     *
     * <p><b>Novo (alerta):</b> fingerprint presente no re-check, AUSENTE nos
     * findings do baseline (o último scan DONE) — ou seja, inédito desde o ship
     * — e não suprimido por triagem. Cria um {@link MonitorAlertStatus#OPEN}
     * novo, ou reabre um {@link MonitorAlertStatus#RESOLVED} (dep voltou a ser
     * vulnerável, §3b).
     *
     * <p><b>Resolução:</b> alerta OPEN cujo fingerprint sumiu do re-check (dep
     * corrigida), passou a constar no baseline (um novo scan já o absorveu como
     * finding normal) ou foi triado como FALSE_POSITIVE/ACCEPTED_RISK.
     *
     * @param baseline último scan DONE, cujos {@code Finding} definem o "estado
     *                 anterior conhecido"; seus componentes foram os re-checados
     */
    @Transactional
    public ReconcileResult reconcile(Project project, Scan baseline, List<VulnFinding> current) {
        Set<String> recheckFps = current.stream()
                .map(VulnFinding::fingerprint).collect(Collectors.toSet());
        Set<String> baselineFps = findingRepository.findByScan(baseline).stream()
                .filter(f -> f.getType() == FindingType.DEPENDENCY_VULN)
                .map(Finding::getFingerprint).collect(Collectors.toSet());
        Set<String> suppressed = triageRepository.findByProjectAndStatusIn(project, SUPPRESSED).stream()
                .map(FindingTriage::getFingerprint).collect(Collectors.toSet());

        Map<String, MonitorAlert> existing = alertRepository.findByProject(project).stream()
                .collect(Collectors.toMap(MonitorAlert::getFingerprint, Function.identity(), (a, b) -> a));

        // Candidatos: fingerprints do re-check inéditos vs. baseline e não suprimidos.
        // Dedup por fingerprint (um mesmo CVE pode vir por >1 GHSA no mesmo re-check).
        LinkedHashMap<String, VulnFinding> candidates = new LinkedHashMap<>();
        for (VulnFinding vf : current) {
            String fp = vf.fingerprint();
            if (baselineFps.contains(fp) || suppressed.contains(fp)) {
                continue;
            }
            candidates.putIfAbsent(fp, vf);
        }

        LocalDateTime now = LocalDateTime.now();
        List<MonitorAlert> newlyAlerted = new ArrayList<>();
        for (VulnFinding vf : candidates.values()) {
            MonitorAlert alert = existing.get(vf.fingerprint());
            if (alert == null) {
                newlyAlerted.add(alertRepository.save(newAlert(project, vf, now)));
            } else if (alert.getStatus() == MonitorAlertStatus.RESOLVED) {
                reopen(alert, vf, now);
                newlyAlerted.add(alertRepository.save(alert));
            }
            // OPEN já existente: idempotente, nada a fazer.
        }

        int resolved = 0;
        for (MonitorAlert alert : existing.values()) {
            String fp = alert.getFingerprint();
            boolean goneOrKnownOrDismissed =
                    !recheckFps.contains(fp) || baselineFps.contains(fp) || suppressed.contains(fp);
            if (alert.getStatus() == MonitorAlertStatus.OPEN && goneOrKnownOrDismissed) {
                alert.setStatus(MonitorAlertStatus.RESOLVED);
                alert.setResolvedAt(now);
                alertRepository.save(alert);
                resolved++;
            }
        }
        return new ReconcileResult(newlyAlerted, resolved);
    }

    private MonitorAlert newAlert(Project project, VulnFinding vf, LocalDateTime now) {
        return MonitorAlert.builder()
                .project(project)
                .fingerprint(vf.fingerprint())
                .osvId(vf.osvId())
                .cve(primaryCve(vf))
                .severity(vf.severity())
                .affectedPurl(vf.affectedPurl())
                .fixedVersion(vf.fixedVersion())
                .epssScore(vf.epssScore())
                .kevListed(vf.kevListed())
                .status(MonitorAlertStatus.OPEN)
                .detail(writeJson(vf))
                .detectedAt(now)
                .build();
    }

    /** Reabre a mesma linha e refresca os campos que podem ter mudado desde o último estado. */
    private void reopen(MonitorAlert alert, VulnFinding vf, LocalDateTime now) {
        alert.setStatus(MonitorAlertStatus.OPEN);
        alert.setResolvedAt(null);
        alert.setDetectedAt(now);
        alert.setOsvId(vf.osvId());
        alert.setCve(primaryCve(vf));
        alert.setSeverity(vf.severity());
        alert.setAffectedPurl(vf.affectedPurl());
        alert.setFixedVersion(vf.fixedVersion());
        alert.setEpssScore(vf.epssScore());
        alert.setKevListed(vf.kevListed());
        alert.setDetail(writeJson(vf));
    }

    private static String primaryCve(VulnFinding vf) {
        return vf.aliases().stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(null);
    }

    private String writeJson(Object o) {
        try {
            return mapper.writeValueAsString(o);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao serializar para jsonb", e);
        }
    }
}
