package com.joao.depguard.server.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.joao.depguard.server.dto.MonitorAlertDto;
import com.joao.depguard.server.model.Project;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;

/**
 * Notifica CVE-novo via POST JSON num webhook de saída (§7, 3c). Resolve a URL
 * do projeto ({@link Project#getNotificationWebhookUrl()}), caindo no fallback
 * global {@code depguard.notifications.webhook-url}; sem nenhuma das duas, é
 * no-op (notificações desabilitadas).
 *
 * <p>Mesma stack HTTP dos clients do GitHub App ({@code java.net.http.HttpClient}
 * + Jackson). <b>Nunca propaga exceção:</b> uma falha de webhook não pode
 * abortar o job de monitoramento nem "perder" o alerta — ele já está persistido
 * (aparece na UI); o webhook é só o empurrão. Falha é logada.
 *
 * <p><b>Nota de segurança (SSRF):</b> a URL é fornecida pelo dono do projeto e
 * chamada pelo servidor. O corpo enviado é só o alerta e a resposta não é
 * exposta ao usuário, mas num deploy multi-tenant vale um allowlist/validação
 * de destino — fora do escopo do MVP.
 */
@Component
public class WebhookNotifier implements MonitorNotifier {

    private static final Logger log = LoggerFactory.getLogger(WebhookNotifier.class);

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    // jsr310 + datas como ISO-8601 (não array de ints), pra bater com o formato
    // da REST API e com o que qualquer consumidor de webhook espera.
    private final ObjectMapper mapper = new ObjectMapper()
            .findAndRegisterModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final String globalWebhookUrl;

    public WebhookNotifier(@Value("${depguard.notifications.webhook-url:}") String globalWebhookUrl) {
        this.globalWebhookUrl = globalWebhookUrl;
    }

    @Override
    public void notifyNewAlerts(Project project, List<MonitorAlertDto> newAlerts) {
        if (newAlerts.isEmpty()) {
            return;
        }
        String url = resolveUrl(project);
        if (url == null || url.isBlank()) {
            return; // sem webhook configurado: notificações desabilitadas
        }
        try {
            String payload = buildPayload(project, newAlerts);
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Content-Type", "application/json")
                    .header("User-Agent", "DepGuard-Monitor")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                log.warn("Webhook de notificação retornou HTTP {} para projeto {}.",
                        resp.statusCode(), project.getId());
            } else {
                log.info("Notificação enviada: {} alerta(s) novo(s) do projeto {} (HTTP {}).",
                        newAlerts.size(), project.getId(), resp.statusCode());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Envio de webhook interrompido para projeto {}.", project.getId());
        } catch (Exception e) {
            log.warn("Falha ao enviar webhook de notificação para projeto {}: {}",
                    project.getId(), e.toString());
        }
    }

    private String buildPayload(Project project, List<MonitorAlertDto> newAlerts) throws Exception {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("event", "monitor.new_alerts");
        ObjectNode proj = payload.putObject("project");
        proj.put("id", project.getId().toString());
        proj.put("name", project.getName());
        payload.put("alertCount", newAlerts.size());
        payload.set("alerts", mapper.valueToTree(newAlerts));
        return mapper.writeValueAsString(payload);
    }

    private String resolveUrl(Project project) {
        String projectUrl = project.getNotificationWebhookUrl();
        return (projectUrl != null && !projectUrl.isBlank()) ? projectUrl : globalWebhookUrl;
    }
}
