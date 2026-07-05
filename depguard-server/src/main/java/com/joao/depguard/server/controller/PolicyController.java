package com.joao.depguard.server.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.server.dto.PolicyDto;
import com.joao.depguard.server.dto.PolicyRequest;
import com.joao.depguard.server.model.Policy;
import com.joao.depguard.server.service.PolicyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/projects/{projectId}/policy")
public class PolicyController {

    private final PolicyService policyService;
    private final ObjectMapper mapper;

    public PolicyController(PolicyService policyService, ObjectMapper mapper) {
        this.policyService = policyService;
        this.mapper = mapper;
    }

    @GetMapping
    public PolicyDto get(@PathVariable UUID projectId) {
        Policy policy = policyService.get(projectId);
        return policy == null ? new PolicyDto(null, mapper.createObjectNode()) : toDto(policy);
    }

    @PutMapping
    public PolicyDto put(@PathVariable UUID projectId, @RequestBody PolicyRequest req) {
        return toDto(policyService.upsert(projectId, req));
    }

    private PolicyDto toDto(Policy policy) {
        try {
            JsonNode rules = mapper.readTree(policy.getRules());
            return new PolicyDto(policy.getId(), rules);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao ler rules persistidas", e);
        }
    }
}
