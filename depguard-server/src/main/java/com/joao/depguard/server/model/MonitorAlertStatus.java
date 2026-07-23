package com.joao.depguard.server.model;

/** Estado de um alerta de monitoramento contínuo (§7). */
public enum MonitorAlertStatus {
    /** CVE novo numa dep já shipada, ainda presente no re-check. */
    OPEN,
    /** A vulnerabilidade sumiu do re-check (dep corrigida) ou foi absorvida por um novo scan. */
    RESOLVED
}
