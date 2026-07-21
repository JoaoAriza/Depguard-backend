package com.joao.depguard.core.secrets.verify;

import com.joao.depguard.core.model.VerificationStatus;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Verifica tokens do GitHub ({@code DG-SECRET-GITHUB-TOKEN}) chamando
 * {@code GET /user} com o token como bearer: 200 = ativo, 401 = inválido.
 *
 * <p>Confirmado contra a API real: token inválido devolve 401 "Bad
 * credentials"; token válido devolve 200. Qualquer outra resposta (403 de
 * rate-limit, erro de rede) vira NOT_CHECKED — não dá pra afirmar que a
 * credencial está morta, e afirmar que está deixaria uma viva escapar.
 */
public class GithubTokenVerifier implements SecretVerifier {

    private static final String DEFAULT_API = "https://api.github.com";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final String apiBase;

    public GithubTokenVerifier() {
        this(DEFAULT_API);
    }

    /** Base injetável só pra teste; produção sempre usa api.github.com. */
    GithubTokenVerifier(String apiBase) {
        this.apiBase = apiBase;
    }

    @Override
    public boolean supports(String ruleId) {
        return "DG-SECRET-GITHUB-TOKEN".equals(ruleId);
    }

    @Override
    public VerificationStatus verify(String rawValue) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(apiBase + "/user"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization", "Bearer " + rawValue)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .GET()
                    .build();
            HttpResponse<Void> resp = http.send(req, HttpResponse.BodyHandlers.discarding());
            return switch (resp.statusCode()) {
                case 200 -> VerificationStatus.VERIFIED;
                case 401 -> VerificationStatus.UNVERIFIED;
                // 403 (rate-limit), 5xx, etc.: não dá pra determinar.
                default -> VerificationStatus.NOT_CHECKED;
            };
        } catch (Exception e) {
            // Timeout, DNS, rede offline: não checado, NÃO "inválido".
            return VerificationStatus.NOT_CHECKED;
        }
    }
}
