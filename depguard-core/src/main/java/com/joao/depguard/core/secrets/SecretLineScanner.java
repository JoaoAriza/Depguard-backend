package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.SecretFinding;
import com.joao.depguard.core.model.VerificationStatus;
import com.joao.depguard.core.util.Fingerprints;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Detecção por linha (regras + entropia genérica), extraída de
 * {@link WorkingTreeSecretScanner} pra ser reaproveitada por qualquer modo de
 * varredura (WORKING_TREE varre todas as linhas do arquivo; PR_DIFF varre só
 * as linhas adicionadas — docs/architecture.md §3.2). A lógica de detecção
 * por linha é idêntica nos dois; só muda de onde as linhas vêm.
 */
class SecretLineScanner {

    private final List<SecretRule> rules;
    private final GenericHighEntropyDetector genericDetector = new GenericHighEntropyDetector();

    SecretLineScanner(List<SecretRule> rules) {
        this.rules = rules;
    }

    /** Working tree / PR diff: o segredo está no checkout, não há commit a atribuir. */
    List<SecretFinding> scanLine(Path relativePath, int lineNumber, String line, AllowlistMatcher allow) {
        return scanLine(relativePath, lineNumber, line, allow, null);
    }

    List<SecretFinding> scanLine(Path relativePath, int lineNumber, String line, AllowlistMatcher allow,
                                  String commitSha) {
        List<SecretFinding> findings = new ArrayList<>();

        for (SecretRule rule : rules) {
            Matcher m = rule.pattern().matcher(line);
            while (m.find()) {
                addFinding(findings, rule.id(), relativePath, lineNumber, m.group(),
                        ShannonEntropy.of(m.group()), allow, commitSha);
            }
        }

        for (GenericHighEntropyDetector.MatchCandidate c : genericDetector.find(line)) {
            addFinding(findings, "DG-SECRET-GENERIC-HIGH-ENTROPY", relativePath, lineNumber,
                    c.value(), ShannonEntropy.of(c.value()), allow, commitSha);
        }

        return findings;
    }

    private void addFinding(List<SecretFinding> findings, String ruleId, Path relativePath,
                             int line, String value, double entropy, AllowlistMatcher allow,
                             String commitSha) {
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
                commitSha, // null fora do modo GIT_HISTORY
                SecretMasking.mask(value),
                secretHash,
                entropy,
                VerificationStatus.NOT_CHECKED,
                false
        ));
    }
}
