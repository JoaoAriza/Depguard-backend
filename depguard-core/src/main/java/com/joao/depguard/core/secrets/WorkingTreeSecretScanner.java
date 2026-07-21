package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.secrets.verify.SecretVerification;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Varre o working tree em busca de segredos (docs/architecture.md §3.2, modo
 * WORKING_TREE). Combina regras por provedor + detector genérico de entropia,
 * aplica filtro de placeholder e allowlist, e nunca guarda o valor cru.
 */
public class WorkingTreeSecretScanner {

    private static final List<String> SKIP_DIR_NAMES =
            List.of(".git", "node_modules", "target", "dist", "build", ".idea", ".vscode");

    private final SecretLineScanner lineScanner;

    public WorkingTreeSecretScanner() {
        this(SecretRules.defaults());
    }

    public WorkingTreeSecretScanner(List<SecretRule> rules) {
        this.lineScanner = new SecretLineScanner(rules);
    }

    public List<SecretFinding> scan(Path repoRoot, Allowlist allowlist) {
        return scan(repoRoot, allowlist, SecretVerification.disabled());
    }

    public List<SecretFinding> scan(Path repoRoot, Allowlist allowlist, SecretVerification verification) {
        AllowlistMatcher allow = new AllowlistMatcher(allowlist);
        List<SecretFinding> findings = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(repoRoot)) {
            List<Path> files = paths
                    .filter(Files::isRegularFile)
                    .filter(p -> !isInSkippedDir(repoRoot, p))
                    .toList();

            for (Path file : files) {
                findings.addAll(scanFile(repoRoot, file, allow, verification));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao percorrer " + repoRoot, e);
        }

        return findings;
    }

    private boolean isInSkippedDir(Path repoRoot, Path file) {
        Path relative = repoRoot.relativize(file);
        for (Path part : relative) {
            if (SKIP_DIR_NAMES.contains(part.toString())) {
                return true;
            }
        }
        return false;
    }

    private List<SecretFinding> scanFile(Path repoRoot, Path file, AllowlistMatcher allow,
                                          SecretVerification verification) {
        Path relative = repoRoot.relativize(file);
        List<SecretFinding> findings = new ArrayList<>();

        List<String> lines;
        try {
            lines = Files.readAllLines(file);
        } catch (IOException e) {
            return findings; // binário ou não-texto (decode inválido): ignora
        } catch (RuntimeException e) {
            return findings;
        }

        for (int i = 0; i < lines.size(); i++) {
            findings.addAll(lineScanner.scanLine(relative, i + 1, lines.get(i), allow, null, verification));
        }

        return findings;
    }
}
