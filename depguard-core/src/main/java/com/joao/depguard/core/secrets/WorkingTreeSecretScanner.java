package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.VerificationStatus;
import com.joao.depguard.core.util.Fingerprints;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.stream.Stream;

/**
 * Varre o working tree em busca de segredos (docs/architecture.md §3.2, modo
 * WORKING_TREE). Combina regras por provedor + detector genérico de entropia,
 * aplica filtro de placeholder e allowlist, e nunca guarda o valor cru.
 */
public class WorkingTreeSecretScanner {

    private static final List<String> SKIP_DIR_NAMES =
            List.of(".git", "node_modules", "target", "dist", "build", ".idea", ".vscode");

    private final List<SecretRule> rules;
    private final GenericHighEntropyDetector genericDetector = new GenericHighEntropyDetector();

    public WorkingTreeSecretScanner() {
        this(SecretRules.defaults());
    }

    public WorkingTreeSecretScanner(List<SecretRule> rules) {
        this.rules = rules;
    }

    public List<SecretFinding> scan(Path repoRoot, Allowlist allowlist) {
        AllowlistMatcher allow = new AllowlistMatcher(allowlist);
        List<SecretFinding> findings = new ArrayList<>();

        try (Stream<Path> paths = Files.walk(repoRoot)) {
            List<Path> files = paths
                    .filter(Files::isRegularFile)
                    .filter(p -> !isInSkippedDir(repoRoot, p))
                    .toList();

            for (Path file : files) {
                findings.addAll(scanFile(repoRoot, file, allow));
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

    private List<SecretFinding> scanFile(Path repoRoot, Path file, AllowlistMatcher allow) {
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
            String line = lines.get(i);

            for (SecretRule rule : rules) {
                Matcher m = rule.pattern().matcher(line);
                while (m.find()) {
                    String value = m.group();
                    addFinding(findings, rule.id(), relative, i + 1, value,
                            ShannonEntropy.of(value), allow);
                }
            }

            for (GenericHighEntropyDetector.MatchCandidate c : genericDetector.find(line)) {
                addFinding(findings, "DG-SECRET-GENERIC-HIGH-ENTROPY", relative, i + 1,
                        c.value(), ShannonEntropy.of(c.value()), allow);
            }
        }

        return findings;
    }

    private void addFinding(List<SecretFinding> findings, String ruleId, Path relativePath,
                             int line, String value, double entropy, AllowlistMatcher allow) {
        if (PlaceholderFilter.isPlaceholder(value)) {
            return;
        }
        if (allow.isAllowlistedPath(relativePath) || allow.isAllowlistedValue(value)) {
            return; // suprimido: nem vira finding
        }

        String pathStr = relativePath.toString().replace('\\', '/');
        String secretHash = Fingerprints.sha256Hex(value);
        String fingerprint = Fingerprints.sha256Hex(ruleId + ":" + pathStr + ":" + secretHash);

        if (allow.isAllowlistedFingerprint(fingerprint)) {
            return;
        }

        findings.add(new SecretFinding(
                fingerprint,
                ruleId,
                pathStr,
                line,
                line,
                null, // commitSha — só em GIT_HISTORY
                SecretMasking.mask(value),
                secretHash,
                entropy,
                VerificationStatus.NOT_CHECKED,
                false
        ));
    }
}
