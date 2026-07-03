package com.joao.depguard.server.dto;

public record AuthResponse(String token, UserDto user) {}
