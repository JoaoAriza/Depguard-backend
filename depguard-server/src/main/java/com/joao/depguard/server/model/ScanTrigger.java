package com.joao.depguard.server.model;

/** O que disparou o scan. */
public enum ScanTrigger {
    MANUAL,
    CI,
    WEBHOOK,
    SCHEDULED,
    /** Resultado escaneado pela CLI e enviado ao server via upload (não rodado aqui). */
    CLI
}
