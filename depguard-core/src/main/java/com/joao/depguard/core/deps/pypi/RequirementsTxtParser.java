package com.joao.depguard.core.deps.pypi;

import com.joao.depguard.core.model.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser best-effort de requirements.txt: só extrai pins exatos
 * ("nome==versão"). Ranges ({@code >=}, {@code ~=} etc.), includes
 * ({@code -r}), opções ({@code -e}, {@code --index-url}) e URLs de VCS são
 * ignorados — sem rodar pip de verdade não há como saber a versão exata
 * resolvida para eles. Por isso um scan que caiu neste fallback é sempre
 * marcado {@code partial} pelo {@code DefaultScanner}, mesmo espírito do
 * fallback do npm sem lockfile (docs/architecture.md §2.1).
 *
 * <p>Como requirements.txt não tem estrutura de árvore, todo componente
 * encontrado sai como {@code direct=true, depth=0} — não há como saber quais
 * seriam transitivos.
 */
public class RequirementsTxtParser {

    private static final Pattern EXACT_PIN = Pattern.compile(
            "^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\\[[^\\]]*])?\\s*==\\s*([A-Za-z0-9.!+*_-]+)");

    public List<Component> parse(Path requirementsTxt) {
        List<String> lines;
        try {
            lines = Files.readAllLines(requirementsTxt);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler " + requirementsTxt, e);
        }

        List<Component> out = new ArrayList<>();
        for (String rawLine : lines) {
            String line = stripComment(rawLine).trim();
            if (line.isEmpty() || line.startsWith("-")) {
                continue; // opções (-e, -r, --index-url...) — não resolvíveis aqui
            }
            line = stripEnvironmentMarker(line);

            Matcher m = EXACT_PIN.matcher(line);
            if (m.find()) {
                String name = PyPiNormalizer.normalize(m.group(1));
                String version = m.group(2);
                out.add(new Component("pypi", name, version,
                        PoetryLockParser.toPurl(name, version), true, 0, List.of()));
            }
            // ranges (>=, ~=, sem versão...) são ignorados de propósito: não há
            // como saber a versão exata resolvida sem um resolver de verdade.
        }
        return out;
    }

    private String stripComment(String line) {
        int idx = line.indexOf('#');
        return idx >= 0 ? line.substring(0, idx) : line;
    }

    private String stripEnvironmentMarker(String line) {
        int idx = line.indexOf(';');
        return idx >= 0 ? line.substring(0, idx).trim() : line;
    }
}
