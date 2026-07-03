package com.joao.depguard.server.dto;

/**
 * Auto-registro: cria uma {@code Organization} nova e seu primeiro usuário
 * (role OWNER). Sem CNPJ/plano/2FA — isso é específico do CyberAudit, fora
 * do escopo do MVP do DepGuard (ver docs/architecture.md).
 */
public record RegisterRequest(
        String organizationName,
        String name,
        String email,
        String password
) {}
