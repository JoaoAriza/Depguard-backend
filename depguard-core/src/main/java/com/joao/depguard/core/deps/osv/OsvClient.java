package com.joao.depguard.core.deps.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementação de rede do {@link OsvApi} sobre api.osv.dev usando o
 * HttpClient nativo (sem cliente HTTP extra no core).
 *
 * <p>NÃO é exercitada pelos testes unitários (não bate na rede no {@code mvn test}).
 */
public class OsvClient implements OsvApi {

    private static final String DEFAULT_BASE_URL = "https://api.osv.dev";

    private final String baseUrl;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public OsvClient() {
        this(DEFAULT_BASE_URL);
    }

    public OsvClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    @Override
    public List<List<String>> queryBatch(List<OsvPackageQuery> queries) {
        ObjectNode body = mapper.createObjectNode();
        ArrayNode arr = body.putArray("queries");
        for (OsvPackageQuery q : queries) {
            ObjectNode qn = arr.addObject();
            qn.put("version", q.version());
            ObjectNode pkg = qn.putObject("package");
            pkg.put("name", q.name());
            pkg.put("ecosystem", osvEcosystem(q.ecosystem()));
        }

        JsonNode resp = post("/v1/querybatch", body);
        List<List<String>> out = new ArrayList<>();
        JsonNode results = resp.get("results");
        if (results != null && results.isArray()) {
            for (JsonNode r : results) {
                List<String> ids = new ArrayList<>();
                JsonNode vulns = r.get("vulns");
                if (vulns != null && vulns.isArray()) {
                    for (JsonNode v : vulns) {
                        ids.add(v.get("id").asText());
                    }
                }
                out.add(ids);
            }
        }
        return out;
    }

    @Override
    public JsonNode getVuln(String id) {
        return get("/v1/vulns/" + id);
    }

    /** OSV usa "npm" para o ecossistema Node; ponto de tradução para futuros ecossistemas. */
    private String osvEcosystem(String ecosystem) {
        return ecosystem;
    }

    private JsonNode post(String path, JsonNode body) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            return mapper.readTree(resp.body());
        } catch (IOException e) {
            throw new UncheckedIOException("Falha no POST " + path, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido no POST " + path, e);
        }
    }

    private JsonNode get(String path) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 404) {
                return null;
            }
            return mapper.readTree(resp.body());
        } catch (IOException e) {
            throw new UncheckedIOException("Falha no GET " + path, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido no GET " + path, e);
        }
    }
}
