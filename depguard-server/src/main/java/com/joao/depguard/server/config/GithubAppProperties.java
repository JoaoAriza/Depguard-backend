package com.joao.depguard.server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Sem defaults de propósito: diferente de {@link JwtProperties} (que tem um
 * valor de dev sensato), não existe um "App ID de exemplo" ou "chave privada
 * padrão" que faça sentido. Ausência aqui deve falhar explícito no primeiro
 * uso (ver {@code GithubAppAuthenticator}), não silenciosamente virar string
 * vazia.
 */
@Component
@ConfigurationProperties(prefix = "github.app")
public class GithubAppProperties {

    private String id;
    private String privateKeyPath;
    private String webhookSecret;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPrivateKeyPath() {
        return privateKeyPath;
    }

    public void setPrivateKeyPath(String privateKeyPath) {
        this.privateKeyPath = privateKeyPath;
    }

    public String getWebhookSecret() {
        return webhookSecret;
    }

    public void setWebhookSecret(String webhookSecret) {
        this.webhookSecret = webhookSecret;
    }
}
