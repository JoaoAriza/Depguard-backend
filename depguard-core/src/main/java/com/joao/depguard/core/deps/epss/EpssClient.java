package com.joao.depguard.core.deps.epss;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Implementação de rede do {@link EpssApi} sobre api.first.org. Consulta em
 * lotes de {@value #BATCH_SIZE} CVEs por request (o parâmetro {@code limit}
 * observado na API real é 100 por resposta — batching evita depender de
 * comportamento de paginação não documentado).
 */
public class EpssClient implements EpssApi {

    private static final String DEFAULT_BASE_URL = "https://api.first.org";
    private static final int BATCH_SIZE = 100;

    private final String baseUrl;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    public EpssClient() {
        this(DEFAULT_BASE_URL);
    }

    public EpssClient(String baseUrl) {
        this.baseUrl = baseUrl;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
    }

    @Override
    public Map<String, Double> queryBatch(List<String> cveIds) {
        Map<String, Double> out = new HashMap<>();
        for (int i = 0; i < cveIds.size(); i += BATCH_SIZE) {
            List<String> batch = cveIds.subList(i, Math.min(i + BATCH_SIZE, cveIds.size()));
            out.putAll(queryOneBatch(batch));
        }
        return out;
    }

    private Map<String, Double> queryOneBatch(List<String> batch) {
        String csv = String.join(",", batch);
        String url = baseUrl + "/data/v1/epss?cve=" + csv + "&limit=" + BATCH_SIZE;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            JsonNode root = mapper.readTree(resp.body());

            Map<String, Double> out = new HashMap<>();
            JsonNode data = root.get("data");
            if (data != null && data.isArray()) {
                for (JsonNode entry : data) {
                    JsonNode cve = entry.get("cve");
                    JsonNode epss = entry.get("epss");
                    if (cve != null && epss != null) {
                        out.put(cve.asText(), Double.parseDouble(epss.asText()));
                    }
                }
            }
            return out;
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao consultar EPSS", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido consultando EPSS", e);
        }
    }
}
