package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.ChangedFile;
import com.joao.depguard.core.model.SecretFinding;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Varre só as linhas ADICIONADAS de um conjunto de arquivos alterados
 * (docs/architecture.md §3.2, modo PR_DIFF) — mesma detecção por linha do
 * WORKING_TREE (via {@link SecretLineScanner}), só muda a fonte das linhas.
 * Rápido e não reacusa segredo pré-existente que o PR não tocou.
 */
public class PrDiffSecretScanner {

    private final SecretLineScanner lineScanner;

    public PrDiffSecretScanner() {
        this(SecretRules.defaults());
    }

    public PrDiffSecretScanner(List<SecretRule> rules) {
        this.lineScanner = new SecretLineScanner(rules);
    }

    public List<SecretFinding> scan(List<ChangedFile> changedFiles, Allowlist allowlist) {
        AllowlistMatcher allow = new AllowlistMatcher(allowlist);
        List<SecretFinding> findings = new ArrayList<>();

        for (ChangedFile file : changedFiles) {
            Path relative = Path.of(file.path());
            for (DiffPatchParser.AddedLine added : DiffPatchParser.addedLines(file.patch())) {
                findings.addAll(lineScanner.scanLine(relative, added.lineNumber(), added.text(), allow));
            }
        }

        return findings;
    }
}
