package com.joao.depguard.server.github;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Clona o head de um PR num diretório temporário raso (profundidade 1, só o
 * commit pedido) — usado pra ter o código em disco antes de rodar o
 * {@code DefaultScanner} nele (que só sabe escanear um caminho local).
 *
 * <p>Usa o git CLI do sistema via {@link ProcessBuilder} (array de
 * argumentos, nunca concatenação de shell — evita injeção) em vez de JGit:
 * mais simples, e já é uma dependência confiável em qualquer ambiente de
 * CI/dev. GitHub aceita {@code fetch} de um SHA arbitrário diretamente
 * (mesmo mecanismo que o actions/checkout usa).
 */
@Component
public class GithubRepoCloner {

    public Path cloneAtCommit(String cloneUrl, String commitSha, String installationToken) {
        Path dir;
        try {
            dir = Files.createTempDirectory("depguard-pr-");
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao criar diretório temporário", e);
        }

        String authenticatedUrl = withToken(cloneUrl, installationToken);
        try {
            run(dir, "git", "init", "-q");
            run(dir, "git", "remote", "add", "origin", authenticatedUrl);
            run(dir, "git", "fetch", "--depth", "1", "origin", commitSha);
            run(dir, "git", "checkout", "-q", "FETCH_HEAD");
            return dir;
        } catch (RuntimeException e) {
            deleteRecursively(dir);
            throw e;
        }
    }

    public void deleteRecursively(Path dir) {
        try (var paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best-effort — diretório temporário, não crítico se sobrar lixo
                }
            });
        } catch (IOException ignored) {
            // idem
        }
    }

    /** {@code https://x-access-token:<token>@github.com/owner/repo.git} — formato exigido pelo GitHub. */
    private String withToken(String cloneUrl, String token) {
        if (!cloneUrl.startsWith("https://")) {
            throw new IllegalArgumentException("cloneUrl precisa ser https://: " + cloneUrl);
        }
        return "https://x-access-token:" + token + "@" + cloneUrl.substring("https://".length());
    }

    private void run(Path workDir, String... command) {
        try {
            Process process = new ProcessBuilder(command)
                    .directory(workDir.toFile())
                    .redirectErrorStream(true)
                    .start();
            String output = new String(process.getInputStream().readAllBytes());
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("Comando git excedeu o tempo limite: " + safeCommand(command));
            }
            if (process.exitValue() != 0) {
                throw new IllegalStateException(
                        "Comando git falhou (" + safeCommand(command) + "): " + redactToken(output));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao executar " + safeCommand(command), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrompido executando " + safeCommand(command), e);
        }
    }

    /** Nunca deixa o token de instalação vazar em mensagem de exceção/log. */
    private String redactToken(String text) {
        return text.replaceAll("x-access-token:[^@]+@", "x-access-token:***@");
    }

    private String safeCommand(String[] command) {
        return redactToken(List.of(command).toString());
    }
}
