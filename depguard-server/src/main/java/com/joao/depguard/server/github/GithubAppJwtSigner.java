package com.joao.depguard.server.github;

import com.joao.depguard.server.config.GithubAppProperties;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Component;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;

/**
 * Gera o JWT de autenticação do GitHub App (assinado com a chave privada RSA
 * do App, RS256) — é a credencial usada SÓ pra trocar por um token de
 * instalação ({@link GithubInstallationTokenClient}); não serve pra chamar a
 * API "de verdade" diretamente.
 *
 * <p>Regras do GitHub ("Generating a JSON Web Token" nos docs oficiais):
 * {@code iat} com ~60s de folga pra clock skew, {@code exp} no máximo 10 min
 * depois, {@code iss} = App ID.
 *
 * <p>A chave privada do GitHub App vem em PKCS#1 ({@code BEGIN RSA PRIVATE
 * KEY}), que {@code java.security.KeyFactory} não lê nativamente — daí o
 * Bouncy Castle.
 */
@Component
public class GithubAppJwtSigner {

    private final GithubAppProperties properties;
    private volatile PrivateKey cachedPrivateKey;

    public GithubAppJwtSigner(GithubAppProperties properties) {
        this.properties = properties;
    }

    public String sign() {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuedAt(Date.from(now.minusSeconds(60)))
                .expiration(Date.from(now.plusSeconds(9 * 60)))
                .issuer(requireAppId())
                .signWith(privateKey())
                .compact();
    }

    private String requireAppId() {
        if (properties.getId() == null || properties.getId().isBlank()) {
            throw new IllegalStateException(
                    "github.app.id não configurado (env var ou -Dgithub.app.id).");
        }
        return properties.getId();
    }

    private PrivateKey privateKey() {
        PrivateKey key = cachedPrivateKey;
        if (key == null) {
            synchronized (this) {
                key = cachedPrivateKey;
                if (key == null) {
                    key = loadPrivateKey();
                    cachedPrivateKey = key;
                }
            }
        }
        return key;
    }

    private PrivateKey loadPrivateKey() {
        String path = properties.getPrivateKeyPath();
        if (path == null || path.isBlank()) {
            throw new IllegalStateException(
                    "github.app.private-key-path não configurado (env var ou -Dgithub.app.private-key-path).");
        }
        try (Reader reader = new FileReader(path);
             PEMParser pemParser = new PEMParser(reader)) {
            Object parsed = pemParser.readObject();
            if (!(parsed instanceof PEMKeyPair keyPair)) {
                throw new IllegalStateException(
                        "Formato de chave inesperado em " + path + ": " + parsed);
            }
            return new JcaPEMKeyConverter().getKeyPair(keyPair).getPrivate();
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler chave privada em " + path, e);
        }
    }
}
