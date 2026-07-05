package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.TriageStatus;

import java.util.UUID;

public record TriageRequest(TriageStatus status, String note, UUID assigneeId) {}
