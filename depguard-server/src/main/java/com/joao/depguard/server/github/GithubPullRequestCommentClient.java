package com.joao.depguard.server.github;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Posta um comentário no PR (endpoint de "issues" — é o mesmo pra PRs, API
 * do GitHub trata PR como um tipo de issue). Complementa o Check Run: o
 * Check Run é o que bloqueia merge, o comentário é o que dá visibilidade
 * direto na conversa do PR (era um dos dois pilares do pitch original —
 * "comenta no PR e bloqueia merge").
 */
@Component
public class GithubPullRequestCommentClient {

    private static final String API_BASE = "https://api.github.com";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public void postComment(String installationToken, String repoFullName, int prNumber, String markdownBody) {
        try {
            ObjectNode body = mapper.createObjectNode();
            body.put("body", markdownBody);

            HttpRequest req = HttpRequest.newBuilder(
                            URI.create(API_BASE + "/repos/" + repoFullName + "/issues/" + prNumber + "/comments"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Bearer " + installationToken)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                throw new IllegalStateException(
                        "Falha ao comentar no PR (HTTP " + resp.statusCode() + "): " + resp.body());
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao chamar a API do GitHub", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido chamando a API do GitHub", e);
        }
    }
}
