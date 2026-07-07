package com.joao.depguard.core.deps.pypi;

import com.joao.depguard.core.model.Component;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;
import org.tomlj.TomlTable;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Lê {@code poetry.lock} (TOML): array de tabelas {@code [[package]]}, cada
 * uma com {@code name}/{@code version} resolvidos exatos — o equivalente
 * PyPI do {@code package-lock.json} (docs/architecture.md §2.1).
 *
 * <p>LIMITAÇÃO CONHECIDA: diferente do package-lock.json v3, poetry.lock não
 * marca quais pacotes são diretos vs. transitivos (isso só se sabe cruzando
 * com {@code pyproject.toml}, que pode nem estar presente no scan). Todos os
 * componentes saem como {@code direct=true, depth=0} — simplificação
 * documentada, não uma garantia real de "é dependência direta". O mesmo vale
 * para licenças: o formato do poetry.lock não inclui esse campo.
 */
public class PoetryLockParser {

    public List<Component> parse(Path poetryLock) {
        TomlParseResult result;
        try {
            result = Toml.parse(poetryLock);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler " + poetryLock, e);
        }

        if (result.hasErrors()) {
            throw new IllegalStateException(
                    "poetry.lock inválido: " + poetryLock + " — " + result.errors());
        }

        List<Component> out = new ArrayList<>();
        TomlArray packages = result.getArray("package");
        if (packages == null) {
            return out;
        }

        for (int i = 0; i < packages.size(); i++) {
            TomlTable pkg = packages.getTable(i);
            String name = pkg.getString("name");
            String version = pkg.getString("version");
            if (name == null || version == null) {
                continue;
            }
            String normalized = PyPiNormalizer.normalize(name);
            out.add(new Component("pypi", normalized, version,
                    toPurl(normalized, version), true, 0, List.of()));
        }
        return out;
    }

    static String toPurl(String normalizedName, String version) {
        return "pkg:pypi/" + normalizedName + "@" + version;
    }
}
