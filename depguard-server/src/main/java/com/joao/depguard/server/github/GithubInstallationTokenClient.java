package com.joao.depguard.server.github;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Troca o JWT do App ({@link GithubAppJwtSigner}) por um token de
 * instalação — de curta duração (~1h), escopado à instalação específica,
 * usado pra chamar a API "de verdade" (Check Runs, comentários, conteúdo do
 * repo) em nome do repositório.
 */
@Component
public class GithubInstallationTokenClient {

    private static final String API_BASE = "https://api.github.com";

    private final GithubAppJwtSigner jwtSigner;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public GithubInstallationTokenClient(GithubAppJwtSigner jwtSigner) {
        this.jwtSigner = jwtSigner;
    }

    /** @return token de instalação — usar como {@code Authorization: Bearer <token>} nas próximas chamadas. */
    public String createInstallationToken(long installationId) {
        try {
            HttpRequest req = HttpRequest.newBuilder(
                            URI.create(API_BASE + "/app/installations/" + installationId + "/access_tokens"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Authorization", "Bearer " + jwtSigner.sign())
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 201) {
                throw new IllegalStateException(
                        "Falha ao criar token de instalação (HTTP " + resp.statusCode() + "): " + resp.body());
            }
            JsonNode root = mapper.readTree(resp.body());
            return root.get("token").asText();
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao chamar a API do GitHub", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido chamando a API do GitHub", e);
        }
    }
}
