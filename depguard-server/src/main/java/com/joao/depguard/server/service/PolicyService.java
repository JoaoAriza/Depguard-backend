package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.VulnFinding;
import com.joao.depguard.core.policy.PolicyDecision;
import com.joao.depguard.core.policy.PolicyEvaluator;
import com.joao.depguard.core.policy.PolicyRules;
import com.joao.depguard.server.dto.FindingDto;
import com.joao.depguard.server.dto.PolicyRequest;
import com.joao.depguard.server.model.Policy;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.repository.PolicyRepository;
import com.joao.depguard.server.repository.ProjectRepository;
import com.joao.depguard.server.repository.ScanRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

/**
 * CRUD do dado bruto ({@code rules} jsonb, §4) + avaliação das regras contra
 * um scan (§5) — este segundo é o motor de políticas da Fase 2, que substituiu
 * o bloqueio hardcoded do fluxo de PR.
 */
@Service
public class PolicyService {

    private final ProjectRepository projectRepository;
    private final PolicyRepository policyRepository;
    private final ScanRepository scanRepository;
    private final PolicyRulesParser rulesParser;
    private final ObjectMapper mapper;
    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    public PolicyService(ProjectRepository projectRepository,
                          PolicyRepository policyRepository,
                          ScanRepository scanRepository,
                          PolicyRulesParser rulesParser,
                          ObjectMapper mapper) {
        this.projectRepository = projectRepository;
        this.policyRepository = policyRepository;
        this.scanRepository = scanRepository;
        this.rulesParser = rulesParser;
        this.mapper = mapper;
    }

    public Policy get(UUID projectId) {
        return policyRepository.findByProject(getProjectOrThrow(projectId)).orElse(null);
    }

    @Transactional
    public Policy upsert(UUID projectId, PolicyRequest req) {
        // Valida ANTES de gravar: policy inválida salva silenciosamente só
        // apareceria muito depois, quebrando o check de um PR.
        rulesParser.parse(req.rules());

        Project project = getProjectOrThrow(projectId);
        Policy policy = policyRepository.findByProject(project)
                .orElseGet(() -> Policy.builder().project(project).build());
        policy.setRules(req.rules().toString());
        return policyRepository.save(policy);
    }

    /** Regras efetivas do projeto: as configuradas, ou os defaults se não houver policy. */
    public PolicyRules rulesFor(Project project) {
        return policyRepository.findByProject(project)
                .map(p -> rulesParser.parse(readTree(p.getRules())))
                .orElseGet(PolicyRules::defaults);
    }

    /**
     * Avalia a policy do projeto do scan contra os findings informados.
     *
     * <p>Quem chama passa apenas os findings que devem contar — o fluxo de PR
     * já exclui os triados como FALSE_POSITIVE/ACCEPTED_RISK, e a decisão de
     * o que conta não é do motor.
     */
    public PolicyDecision evaluateForScan(UUID scanId, List<FindingDto> findings) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan não encontrado."));

        List<VulnFinding> vulns = findings.stream()
                .filter(f -> f.type() == FindingType.DEPENDENCY_VULN)
                .map(f -> mapper.convertValue(f.detail(), VulnFinding.class))
                .toList();
        List<SecretFinding> secrets = findings.stream()
                .filter(f -> f.type() == FindingType.SECRET)
                .map(f -> mapper.convertValue(f.detail(), SecretFinding.class))
                .toList();

        return evaluator.evaluate(rulesFor(scan.getProject()), vulns, secrets);
    }

    private com.fasterxml.jackson.databind.JsonNode readTree(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao ler rules persistidas", e);
        }
    }

    private Project getProjectOrThrow(UUID projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));
    }
}
