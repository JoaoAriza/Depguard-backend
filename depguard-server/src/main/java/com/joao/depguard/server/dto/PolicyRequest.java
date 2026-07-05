package com.joao.depguard.server.dto;

import com.fasterxml.jackson.databind.JsonNode;

public record PolicyRequest(JsonNode rules) {}
