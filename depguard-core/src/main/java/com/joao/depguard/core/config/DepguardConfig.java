package com.joao.depguard.core.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Config do repositório ({@code .depguard.yml}), versionada junto do código
 * (docs/architecture.md §3.3). Hoje só a allowlist; deixado como objeto de
 * topo pra caber outras seções depois sem quebrar arquivos existentes.
 *
 * <p>{@code @JsonIgnoreProperties(false)} de propósito NÃO usado — campos
 * desconhecidos FALHAM o parse: num arquivo de segurança, um typo silencioso
 * (ex.: {@code fingerprint:} em vez de {@code fingerprints:}) faria a
 * supressão não funcionar sem o dev saber por quê.
 */
@JsonIgnoreProperties(ignoreUnknown = false)
public record DepguardConfig(AllowlistConfig allowlist) {

    @JsonIgnoreProperties(ignoreUnknown = false)
    public record AllowlistConfig(
            List<String> paths,
            List<String> valueRegexes,
            List<String> fingerprints
    ) {}
}
