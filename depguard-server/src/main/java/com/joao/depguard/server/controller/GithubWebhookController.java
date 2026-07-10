package com.joao.depguard.server.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.server.config.GithubAppProperties;
import com.joao.depguard.server.github.GithubPullRequestWebhookHandler;
import com.joao.depguard.server.github.GithubWebhookSignatureVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Recebe webhooks do GitHub App. Público (sem JWT/API key) de propósito — a
 * assinatura HMAC é a própria autenticação (ver {@link GithubWebhookSignatureVerifier}).
 * Precisa estar em {@code /auth/**}? Não — liberado explicitamente no
 * SecurityConfig como {@code /api/v1/webhooks/**}.
 */
@RestController
@RequestMapping("/api/v1/webhooks/github")
public class GithubWebhookController {

    private static final Logger log = LoggerFactory.getLogger(GithubWebhookController.class);

    private final GithubWebhookSignatureVerifier signatureVerifier;
    private final GithubAppProperties properties;
    private final GithubPullRequestWebhookHandler pullRequestHandler;
    private final ObjectMapper mapper = new ObjectMapper();

    public GithubWebhookController(GithubWebhookSignatureVerifier signatureVerifier,
                                    GithubAppProperties properties,
                                    GithubPullRequestWebhookHandler pullRequestHandler) {
        this.signatureVerifier = signatureVerifier;
        this.properties = properties;
        this.pullRequestHandler = pullRequestHandler;
    }

    @PostMapping
    public ResponseEntity<Void> receive(@RequestBody String rawPayload,
                                         @RequestHeader("X-Hub-Signature-256") String signature,
                                         @RequestHeader("X-GitHub-Event") String eventType) {

        if (!signatureVerifier.isValid(rawPayload, properties.getWebhookSecret(), signature)) {
            log.warn("Webhook do GitHub com assinatura inválida — descartado.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        if ("pull_request".equals(eventType)) {
            try {
                JsonNode payload = mapper.readTree(rawPayload);
                pullRequestHandler.handlePullRequestEvent(payload);
            } catch (Exception e) {
                log.error("Falha processando webhook pull_request", e);
            }
        }
        // outros eventos (ex.: "ping", enviado quando o webhook é salvo no
        // GitHub) só recebem 200, sem processamento — comportamento correto.

        return ResponseEntity.ok().build();
    }
}
