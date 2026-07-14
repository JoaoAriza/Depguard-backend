package com.joao.depguard.core.model;

/**
 * Um arquivo alterado num PR/diff, usado pelo modo {@link SecretScanMode#PR_DIFF}.
 * {@code patch} é o diff unificado no formato do GitHub (nulo pra arquivos
 * binários ou diffs grandes demais que o GitHub omite).
 */
public record ChangedFile(String path, String patch) {}
