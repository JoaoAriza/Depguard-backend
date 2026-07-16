package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;
import com.joao.depguard.core.model.SecretFinding;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.diff.DiffEntry;
import org.eclipse.jgit.diff.DiffFormatter;
import org.eclipse.jgit.diff.Edit;
import org.eclipse.jgit.diff.RawText;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.ObjectLoader;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.patch.FileHeader;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.revwalk.RevWalk;
import org.eclipse.jgit.treewalk.EmptyTreeIterator;
import org.eclipse.jgit.treewalk.CanonicalTreeParser;
import org.eclipse.jgit.util.io.DisabledOutputStream;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Varre o HISTÓRICO do git em busca de segredos (docs/architecture.md §3.2,
 * modo GIT_HISTORY). A razão de existir: um segredo deletado continua no
 * histórico — o working tree limpo não prova que nunca vazou.
 *
 * <p>Escaneia só as linhas ADICIONADAS de cada commit (diff contra o primeiro
 * pai), então cada segredo é atribuído ao commit que o introduziu, e não
 * reaparece em todo commit posterior que apenas o carrega. Mesma detecção por
 * linha do working tree, via {@link SecretLineScanner}.
 *
 * <p>Dedup por fingerprint: se o mesmo segredo foi introduzido, removido e
 * reintroduzido, reporta uma vez só (o commit mais recente que o introduziu —
 * o RevWalk anda do mais novo pro mais antigo). Reportar N vezes o mesmo
 * segredo vazado seria só ruído: a triagem é por fingerprint de qualquer forma.
 */
public class GitHistorySecretScanner {

    private final SecretLineScanner lineScanner;

    public GitHistorySecretScanner() {
        this(SecretRules.defaults());
    }

    public GitHistorySecretScanner(List<SecretRule> rules) {
        this.lineScanner = new SecretLineScanner(rules);
    }

    public List<SecretFinding> scan(Path repoRoot, Allowlist allowlist) {
        AllowlistMatcher allow = new AllowlistMatcher(allowlist);
        // LinkedHashMap: dedup por fingerprint preservando a ordem de descoberta.
        Map<String, SecretFinding> byFingerprint = new LinkedHashMap<>();

        try (Git git = Git.open(repoRoot.toFile());
             Repository repo = git.getRepository();
             RevWalk walk = new RevWalk(repo);
             DiffFormatter formatter = new DiffFormatter(DisabledOutputStream.INSTANCE)) {

            ObjectId head = repo.resolve("HEAD");
            if (head == null) {
                return List.of(); // repositório sem nenhum commit
            }

            formatter.setRepository(repo);
            formatter.setDetectRenames(true);

            walk.markStart(walk.parseCommit(head));
            for (RevCommit commit : walk) {
                for (SecretFinding f : scanCommit(repo, walk, formatter, commit, allow)) {
                    byFingerprint.putIfAbsent(f.fingerprint(), f);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao varrer o histórico de " + repoRoot, e);
        }

        return new ArrayList<>(byFingerprint.values());
    }

    private List<SecretFinding> scanCommit(Repository repo, RevWalk walk, DiffFormatter formatter,
                                            RevCommit commit, AllowlistMatcher allow) throws IOException {
        List<SecretFinding> findings = new ArrayList<>();
        String commitSha = commit.getName();

        List<DiffEntry> diffs = commit.getParentCount() == 0
                ? diffAgainstEmptyTree(repo, formatter, commit)
                // Só o primeiro pai: num merge, o conteúdo do segundo pai já foi
                // escaneado na branch dele — diffar contra os dois duplicaria.
                : formatter.scan(walk.parseCommit(commit.getParent(0)).getTree(), commit.getTree());

        for (DiffEntry diff : diffs) {
            if (diff.getChangeType() == DiffEntry.ChangeType.DELETE) {
                continue; // não há conteúdo novo pra escanear
            }
            findings.addAll(scanDiff(repo, formatter, diff, commitSha, allow));
        }

        return findings;
    }

    private List<DiffEntry> diffAgainstEmptyTree(Repository repo, DiffFormatter formatter, RevCommit commit)
            throws IOException {
        // Commit raiz: tudo nele é "adicionado".
        CanonicalTreeParser newTree = new CanonicalTreeParser();
        try (var reader = repo.newObjectReader()) {
            newTree.reset(reader, commit.getTree());
            return formatter.scan(new EmptyTreeIterator(), newTree);
        }
    }

    private List<SecretFinding> scanDiff(Repository repo, DiffFormatter formatter, DiffEntry diff,
                                          String commitSha, AllowlistMatcher allow) throws IOException {
        List<SecretFinding> findings = new ArrayList<>();

        if (!diff.getNewId().isComplete()) {
            return findings;
        }
        ObjectLoader loader = repo.open(diff.getNewId().toObjectId());
        byte[] bytes = loader.getBytes();
        if (RawText.isBinary(bytes)) {
            return findings;
        }

        RawText newText = new RawText(bytes);
        Path relative = Path.of(diff.getNewPath());
        FileHeader header = formatter.toFileHeader(diff);

        Set<Integer> addedLines = new HashSet<>();
        for (Edit edit : header.toEditList()) {
            // INSERT e REPLACE trazem linhas novas no lado B; DELETE não.
            if (edit.getType() == Edit.Type.INSERT || edit.getType() == Edit.Type.REPLACE) {
                for (int i = edit.getBeginB(); i < edit.getEndB(); i++) {
                    addedLines.add(i);
                }
            }
        }

        for (int i : addedLines) {
            if (i >= newText.size()) {
                continue;
            }
            // RawText é 0-based; SecretFinding.lineStart é 1-based.
            findings.addAll(lineScanner.scanLine(relative, i + 1, newText.getString(i), allow, commitSha));
        }

        return findings;
    }
}
