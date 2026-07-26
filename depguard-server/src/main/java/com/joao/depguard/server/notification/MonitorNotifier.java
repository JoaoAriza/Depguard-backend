package com.joao.depguard.server.notification;

import com.joao.depguard.server.dto.MonitorAlertDto;
import com.joao.depguard.server.model.Project;

import java.util.List;

/**
 * Canal de notificação de CVE-novo do monitoramento contínuo (docs/architecture.md
 * §7, 3c). Abstração de propósito: o MVP entrega webhook de saída
 * ({@link WebhookNotifier}); email e issue no GitHub podem ser somados depois
 * sem tocar o {@code MonitorService}.
 *
 * <p>Recebe apenas os alertas <b>novos</b> desta execução (já filtrados por
 * triagem na 3b) — nunca deve re-notificar um alerta já existente.
 */
public interface MonitorNotifier {

    void notifyNewAlerts(Project project, List<MonitorAlertDto> newAlerts);
}
