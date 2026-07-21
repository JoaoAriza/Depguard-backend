package com.joao.depguard.core.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.joao.depguard.core.model.Allowlist;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Lê o {@code .depguard.yml} da raiz do repositório e o converte numa
 * {@link Allowlist} (docs/architecture.md §3.3).
 *
 * <p><b>Só use pra checkout CONFIÁVEL</b> (repo local via CLI, ou o checkout do
 * dono no dashboard). NUNCA leia o {@code .depguard.yml} de um PR não-confiável:
 * um contribuidor poderia, no mesmo PR, allowlistar o segredo que está
 * introduzindo. Quem chama é responsável por essa fronteira de confiança —
 * o fluxo de PR_DIFF não chama isto.
 *
 * <p>Usa data-binding do Jackson pra tipos fixos (sem desserialização
 * polimórfica, sem instanciação arbitrária), então um arquivo malicioso não
 * executa código. Config malformada FALHA explícito ({@link DepguardConfigException})
 * em vez de ser ignorada em silêncio — silêncio esconderia supressão quebrada.
 */
public class DepguardConfigLoader {

    private static final List<String> FILENAMES = List.of(".depguard.yml", ".depguard.yaml");

    // FAIL_ON_UNKNOWN default (não desabilitado): typo de campo vira erro.
    private final ObjectMapper yaml = new ObjectMapper(new YAMLFactory());

    /** @return allowlist do repo, ou {@link Allowlist#empty()} se não houver arquivo. */
    public Allowlist load(Path repoRoot) {
        Path file = null;
        for (String name : FILENAMES) {
            Path candidate = repoRoot.resolve(name);
            if (Files.isRegularFile(candidate)) {
                file = candidate;
                break;
            }
        }
        if (file == null) {
            return Allowlist.empty();
        }

        try {
            String content = Files.readString(file);
            if (content.isBlank()) {
                return Allowlist.empty();
            }
            DepguardConfig config = yaml.readValue(content, DepguardConfig.class);
            return toAllowlist(config);
        } catch (IOException e) {
            throw new DepguardConfigException(
                    "Falha ao ler " + file.getFileName() + ": " + rootMessage(e), e);
        }
    }

    private Allowlist toAllowlist(DepguardConfig config) {
        if (config == null || config.allowlist() == null) {
            return Allowlist.empty();
        }
        DepguardConfig.AllowlistConfig a = config.allowlist();
        return new Allowlist(set(a.paths()), set(a.valueRegexes()), set(a.fingerprints()));
    }

    private Set<String> set(List<String> list) {
        return list == null ? Set.of() : Set.copyOf(list);
    }

    /** Mensagem da causa raiz — o texto do Jackson/snakeyaml diz linha/coluna do erro. */
    private String rootMessage(Throwable t) {
        Throwable root = t;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        return root.getMessage();
    }
}
