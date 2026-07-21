package com.joao.depguard.core.config;

/**
 * {@code .depguard.yml} presente mas inválido (YAML quebrado, campo
 * desconhecido, tipo errado). Falha explícita em vez de ignorar: uma allowlist
 * quebrada silenciosamente não suprimiria nada e o dev não saberia por quê.
 */
public class DepguardConfigException extends RuntimeException {

    public DepguardConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
