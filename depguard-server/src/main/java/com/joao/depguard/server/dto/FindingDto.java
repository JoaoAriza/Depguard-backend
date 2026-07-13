package com.joao.depguard.server.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.model.TriageStatus;

import java.util.UUID;

public record FindingDto(
        UUID id, FindingType type, Severity severity, String fingerprint,
        JsonNode detail, TriageStatus triageStatus, String triageNote
) {}
