package com.joao.depguard.core.deps.kev;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

/**
 * Implementação de rede do {@link KevApi}. Baixa o catálogo inteiro (~1.5MB,
 * ~1600 entradas) por chamada — sem cache de dia próprio no core; quem chama
 * decide a frequência (docs/architecture.md §2.4: "baixar 1x/dia, cachear").
 */
public class KevClient implements KevApi {

    private static final String DEFAULT_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private final String catalogUrl;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public KevClient() {
        this(DEFAULT_URL);
    }

    public KevClient(String catalogUrl) {
        this.catalogUrl = catalogUrl;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
    }

    @Override
    public Set<String> fetchAllCveIds() {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(catalogUrl))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            JsonNode root = mapper.readTree(resp.body());

            Set<String> out = new HashSet<>();
            JsonNode vulns = root.get("vulnerabilities");
            if (vulns != null && vulns.isArray()) {
                for (JsonNode v : vulns) {
                    JsonNode id = v.get("cveID");
                    if (id != null) {
                        out.add(id.asText());
                    }
                }
            }
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao baixar catálogo KEV", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido baixando KEV", e);
        }
    }
}
