package com.joao.depguard.core.deps;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Lê {@code package-lock.json} e devolve a árvore de dependências resolvida
 * com versões exatas.
 *
 * <p>Caminho feliz: lockfileVersion 2/3 (objeto {@code packages} achatado).
 * Também aceita o formato v1 legado (árvore aninhada em {@code dependencies}).
 *
 * <p>O lockfile já traz as versões exatas das transitivas — não reinventamos
 * resolução de range (ver docs/architecture.md §2.1).
 */
public class NpmLockfileParser {

    private static final String NODE_MODULES = "node_modules/";

    private final ObjectMapper mapper = new ObjectMapper();

    /** Parseia um arquivo package-lock.json. Lança {@link UncheckedIOException} se ilegível. */
    public List<Component> parse(Path packageLockJson) {
        try (InputStream in = Files.newInputStream(packageLockJson)) {
            JsonNode root = mapper.readTree(in);

            JsonNode packages = root.get("packages");
            if (packages != null && packages.isObject()) {
                return parsePackages(packages);          // v2/v3
            }

            JsonNode dependencies = root.get("dependencies");
            if (dependencies != null && dependencies.isObject()) {
                List<Component> out = new ArrayList<>();  // v1 legado
                parseLegacyTree(dependencies, 0, out);
                return out;
            }

            return List.of();
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao ler " + packageLockJson, e);
        }
    }

    // --- v2/v3: objeto "packages" achatado --------------------------------

    private List<Component> parsePackages(JsonNode packages) {
        Set<String> directNames = directNames(packages);
        List<Component> out = new ArrayList<>();

        Iterator<Map.Entry<String, JsonNode>> it = packages.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            String key = e.getKey();
            // pula a raiz ("") e pacotes de workspace (sem prefixo node_modules/)
            if (key.isEmpty() || !key.startsWith(NODE_MODULES)) {
                continue;
            }
            JsonNode entry = e.getValue();
            JsonNode versionNode = entry.get("version");
            if (versionNode == null || !versionNode.isTextual()) {
                continue; // links/symlinks/workspaces sem versão resolvida
            }

            String name = key.substring(key.lastIndexOf(NODE_MODULES) + NODE_MODULES.length());
            String version = versionNode.asText();
            boolean direct = key.equals(NODE_MODULES + name) && directNames.contains(name);
            int depth = countOccurrences(key, NODE_MODULES) - 1;

            out.add(new Component("npm", name, version, toPurl(name, version),
                    direct, depth, extractLicenses(entry)));
        }
        return out;
    }

    /** Nomes declarados no package.json da raiz (deps + devDeps + optionalDeps). */
    private Set<String> directNames(JsonNode packages) {
        Set<String> names = new HashSet<>();
        JsonNode rootEntry = packages.get("");
        if (rootEntry != null) {
            addFieldNames(rootEntry.get("dependencies"), names);
            addFieldNames(rootEntry.get("devDependencies"), names);
            addFieldNames(rootEntry.get("optionalDependencies"), names);
        }
        return names;
    }

    private void addFieldNames(JsonNode obj, Set<String> into) {
        if (obj != null && obj.isObject()) {
            obj.fieldNames().forEachRemaining(into::add);
        }
    }

    // --- v1: árvore aninhada em "dependencies" ----------------------------

    private void parseLegacyTree(JsonNode deps, int depth, List<Component> out) {
        Iterator<Map.Entry<String, JsonNode>> it = deps.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            String name = e.getKey();
            JsonNode entry = e.getValue();

            JsonNode versionNode = entry.get("version");
            if (versionNode != null && versionNode.isTextual()) {
                String version = versionNode.asText();
                out.add(new Component("npm", name, version, toPurl(name, version),
                        depth == 0, depth, extractLicenses(entry)));
            }

            JsonNode nested = entry.get("dependencies");
            if (nested != null && nested.isObject()) {
                parseLegacyTree(nested, depth + 1, out);
            }
        }
    }

    // --- helpers ----------------------------------------------------------

    /** Constrói o Package URL canônico, codificando o escopo conforme a purl spec. */
    static String toPurl(String name, String version) {
        if (name.startsWith("@")) {
            int slash = name.indexOf('/');
            if (slash > 0) {
                String scope = name.substring(1, slash); // sem o '@'
                String bare = name.substring(slash + 1);
                return "pkg:npm/%40" + scope + "/" + bare + "@" + version;
            }
        }
        return "pkg:npm/" + name + "@" + version;
    }

    private List<String> extractLicenses(JsonNode entry) {
        JsonNode license = entry.get("license");
        if (license != null) {
            if (license.isTextual()) {
                return List.of(license.asText());
            }
            if (license.isObject() && license.hasNonNull("type")) {
                return List.of(license.get("type").asText());
            }
        }
        JsonNode licenses = entry.get("licenses");
        if (licenses != null && licenses.isArray()) {
            List<String> out = new ArrayList<>();
            for (JsonNode n : licenses) {
                if (n.isTextual()) {
                    out.add(n.asText());
                } else if (n.isObject() && n.hasNonNull("type")) {
                    out.add(n.get("type").asText());
                }
            }
            if (!out.isEmpty()) {
                return out;
            }
        }
        return List.of();
    }

    private int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}
