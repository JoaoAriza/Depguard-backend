package com.joao.depguard.server.github;

import com.fasterxml.jackson.databind.JsonNode;
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
 * Cria/atualiza um Check Run — é o mecanismo que aparece na aba "Checks" do
 * PR e, se o repositório marcar esse check como obrigatório (branch
 * protection, configurado pelo dono do repo — não pelo App), bloqueia o
 * merge quando o conclusion é {@code failure}.
 */
@Component
public class GithubCheckRunClient {

    private static final String API_BASE = "https://api.github.com";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    /** @return id do check run criado — necessário pra depois atualizar (patchCompleted). */
    public long createInProgress(String installationToken, String repoFullName, String headSha, String name) {
        ObjectNode body = mapper.createObjectNode();
        body.put("name", name);
        body.put("head_sha", headSha);
        body.put("status", "in_progress");

        JsonNode resp = post("/repos/" + repoFullName + "/check-runs", installationToken, body);
        return resp.get("id").asLong();
    }

    public void patchCompleted(String installationToken, String repoFullName, long checkRunId,
                                String conclusion, String summaryTitle, String summaryText) {
        ObjectNode body = mapper.createObjectNode();
        body.put("status", "completed");
        body.put("conclusion", conclusion);
        ObjectNode output = body.putObject("output");
        output.put("title", summaryTitle);
        output.put("summary", summaryText);

        patch("/repos/" + repoFullName + "/check-runs/" + checkRunId, installationToken, body);
    }

    private JsonNode post(String path, String token, JsonNode body) {
        return send("POST", path, token, body);
    }

    private JsonNode patch(String path, String token, JsonNode body) {
        return send("PATCH", path, token, body);
    }

    private JsonNode send(String method, String path, String token, JsonNode body) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(API_BASE + path))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                throw new IllegalStateException(
                        method + " " + path + " falhou (HTTP " + resp.statusCode() + "): " + resp.body());
            }
            return mapper.readTree(resp.body());
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao chamar " + method + " " + path, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido chamando " + method + " " + path, e);
        }
    }
}
