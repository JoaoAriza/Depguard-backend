package com.joao.depguard.server.dto;

import com.joao.depguard.core.model.Engine;

import java.util.Set;

/**
 * MVP: {@code repoPath} é um caminho local acessível pelo processo do
 * servidor (mesmo modelo da CLI). Clonar repositório remoto via GitHub App é
 * Fase 1 (docs/architecture.md §8) — fora do escopo deste passo.
 */
public record SubmitScanRequest(String repoPath, Set<Engine> engines) {}
