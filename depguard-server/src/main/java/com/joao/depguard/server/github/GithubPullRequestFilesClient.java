package com.joao.depguard.server.github;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.ChangedFile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lista os arquivos alterados de um PR (GET .../pulls/{n}/files) — a fonte
 * do modo {@link com.joao.depguard.core.model.SecretScanMode#PR_DIFF}. O
 * campo {@code patch} vem nulo pra arquivo binário ou diff grande demais
 * (o GitHub omite); {@link com.joao.depguard.core.secrets.DiffPatchParser}
 * já trata isso como "sem linha adicionada".
 */
@Component
public class GithubPullRequestFilesClient {

    private static final String API_BASE = "https://api.github.com";
    private static final Pattern NEXT_LINK = Pattern.compile("<([^>]+)>;\\s*rel=\"next\"");

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public List<ChangedFile> listChangedFiles(String installationToken, String repoFullName, int prNumber) {
        List<ChangedFile> result = new ArrayList<>();
        String url = API_BASE + "/repos/" + repoFullName + "/pulls/" + prNumber + "/files?per_page=100";

        while (url != null) {
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(30))
                        .header("Authorization", "Bearer " + installationToken)
                        .header("Accept", "application/vnd.github+json")
                        .header("X-GitHub-Api-Version", "2022-11-28")
                        .GET()
                        .build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() >= 300) {
                    throw new IllegalStateException(
                            "Falha ao listar arquivos do PR (HTTP " + resp.statusCode() + "): " + resp.body());
                }

                for (JsonNode item : mapper.readTree(resp.body())) {
                    String path = item.get("filename").asText();
                    JsonNode patchNode = item.get("patch");
                    String patch = patchNode != null && !patchNode.isNull() ? patchNode.asText() : null;
                    result.add(new ChangedFile(path, patch));
                }

                url = nextPageUrl(resp.headers().firstValue("Link").orElse(null));
            } catch (IOException e) {
                throw new UncheckedIOException("Falha ao chamar a API do GitHub", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrompido chamando a API do GitHub", e);
            }
        }

        return result;
    }

    private String nextPageUrl(String linkHeader) {
        if (linkHeader == null) {
            return null;
        }
        Matcher m = NEXT_LINK.matcher(linkHeader);
        return m.find() ? m.group(1) : null;
    }
}
