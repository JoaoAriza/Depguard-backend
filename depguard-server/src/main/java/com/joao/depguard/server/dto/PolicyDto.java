package com.joao.depguard.server.dto;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.UUID;

public record PolicyDto(UUID id, JsonNode rules) {}
