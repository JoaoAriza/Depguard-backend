package com.joao.depguard.server.model;

/** O que disparou o scan. */
public enum ScanTrigger {
    MANUAL,
    CI,
    WEBHOOK,
    SCHEDULED
}
