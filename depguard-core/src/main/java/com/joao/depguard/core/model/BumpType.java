package com.joao.depguard.core.model;

/** Tipo do salto de versão necessário para chegar na menor versão segura. */
public enum BumpType {
    PATCH,
    MINOR,
    MAJOR,
    /** Não há correção conhecida / não aplicável. */
    NONE
}
