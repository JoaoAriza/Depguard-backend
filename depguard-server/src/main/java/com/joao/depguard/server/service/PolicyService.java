package com.joao.depguard.server.service;

import com.joao.depguard.server.dto.PolicyRequest;
import com.joao.depguard.server.model.Policy;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.repository.PolicyRepository;
import com.joao.depguard.server.repository.ProjectRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/**
 * Motor de avaliação de políticas é Fase 2 (docs/architecture.md §8) — aqui
 * é só o CRUD do dado bruto ({@code rules} jsonb), como já estava escopado
 * no §4.
 */
@Service
public class PolicyService {

    private final ProjectRepository projectRepository;
    private final PolicyRepository policyRepository;

    public PolicyService(ProjectRepository projectRepository, PolicyRepository policyRepository) {
        this.projectRepository = projectRepository;
        this.policyRepository = policyRepository;
    }

    public Policy get(UUID projectId) {
        return policyRepository.findByProject(getProjectOrThrow(projectId)).orElse(null);
    }

    @Transactional
    public Policy upsert(UUID projectId, PolicyRequest req) {
        Project project = getProjectOrThrow(projectId);
        Policy policy = policyRepository.findByProject(project)
                .orElseGet(() -> Policy.builder().project(project).build());
        policy.setRules(req.rules().toString());
        return policyRepository.save(policy);
    }

    private Project getProjectOrThrow(UUID projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Projeto não encontrado."));
    }
}
