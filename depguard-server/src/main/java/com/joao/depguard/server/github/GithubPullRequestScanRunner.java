package com.joao.depguard.server.github;

import com.joao.depguard.core.model.ChangedFile;
import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.SecretScanMode;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.dto.FindingDto;
import com.joao.depguard.server.model.TriageStatus;
import com.joao.depguard.server.service.FindingService;
import com.joao.depguard.server.service.ScanExecutionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Trabalho pesado do fluxo de PR: clona o head do commit, reaproveita
 * {@code ScanExecutionService.runSync} (mesma persistência do fluxo do
 * dashboard — Finding/ScanComponent/Sbom), e reporta o resultado de volta
 * pro GitHub (Check Run + comentário).
 */
@Service
public class GithubPullRequestScanRunner {

    private static final Logger log = LoggerFactory.getLogger(GithubPullRequestScanRunner.class);

    private final FindingService findingService;
    private final ScanExecutionService scanExecutionService;
    private final GithubRepoCloner repoCloner;
    private final GithubCheckRunClient checkRunClient;
    private final GithubPullRequestCommentClient commentClient;
    private final GithubPullRequestFilesClient filesClient;

    public GithubPullRequestScanRunner(FindingService findingService,
                                        ScanExecutionService scanExecutionService,
                                        GithubRepoCloner repoCloner,
                                        GithubCheckRunClient checkRunClient,
                                        GithubPullRequestCommentClient commentClient,
                                        GithubPullRequestFilesClient filesClient) {
        this.findingService = findingService;
        this.scanExecutionService = scanExecutionService;
        this.repoCloner = repoCloner;
        this.checkRunClient = checkRunClient;
        this.commentClient = commentClient;
        this.filesClient = filesClient;
    }

    @Async
    public void runAsync(UUID scanId, String cloneUrl, String headSha, String token,
                          String repoFullName, long checkRunId, int prNumber) {
        Path clonedRepo = null;
        try {
            clonedRepo = repoCloner.cloneAtCommit(cloneUrl, headSha, token);
            // Segredos em PR_DIFF (só o que o PR adiciona); dependências ainda
            // usam o clone completo — lockfile precisa da árvore inteira.
            List<ChangedFile> changedFiles = filesClient.listChangedFiles(token, repoFullName, prNumber);
            boolean success = scanExecutionService.runSync(
                    scanId, clonedRepo, Set.of(Engine.DEPENDENCIES, Engine.SECRETS),
                    SecretScanMode.PR_DIFF, changedFiles);

            if (!success) {
                checkRunClient.patchCompleted(token, repoFullName, checkRunId, "failure",
                        "DepGuard: erro ao escanear",
                        "O scan não terminou corretamente. Veja os logs do servidor.");
                return;
            }

            List<FindingDto> findings = findingService.listByScan(scanId, null, null, null);
            report(token, repoFullName, checkRunId, prNumber, findings);
        } catch (Exception e) {
            log.error("Falha processando PR #{} de {}", prNumber, repoFullName, e);
            checkRunClient.patchCompleted(token, repoFullName, checkRunId, "failure",
                    "DepGuard: erro ao escanear", "Erro inesperado: " + e.getMessage());
        } finally {
            if (clonedRepo != null) {
                repoCloner.deleteRecursively(clonedRepo);
            }
        }
    }

    /**
     * Política de bloqueio provisória pro MVP (Fase 1): falha o check se
     * houver QUALQUER segredo ou vulnerabilidade CRITICAL/HIGH. O motor de
     * políticas de verdade, configurável por projeto (regras já persistidas
     * em {@code Policy} desde o Passo 7), é Fase 2 — aqui é só um default
     * fixo pra já ter um sinal de bloqueio funcionando.
     *
     * FALSE_POSITIVE/ACCEPTED_RISK não contam pro bloqueio — já foram
     * triados por um humano; contar mesmo assim tornaria a triagem inútil
     * pro caso de uso que mais importa (liberar o merge).
     */
    private void report(String token, String repoFullName, long checkRunId, int prNumber, List<FindingDto> findings) {
        List<FindingDto> actionable = findings.stream()
                .filter(f -> f.triageStatus() != TriageStatus.FALSE_POSITIVE
                        && f.triageStatus() != TriageStatus.ACCEPTED_RISK)
                .toList();

        long secretCount = actionable.stream().filter(f -> f.type() == FindingType.SECRET).count();
        long vulnCount = actionable.stream().filter(f -> f.type() == FindingType.DEPENDENCY_VULN).count();
        long criticalOrHigh = actionable.stream()
                .filter(f -> f.type() == FindingType.DEPENDENCY_VULN)
                .filter(f -> f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH)
                .count();

        boolean blocking = secretCount > 0 || criticalOrHigh > 0;
        String conclusion = blocking ? "failure" : "success";
        String title = blocking
                ? "DepGuard encontrou problemas que bloqueiam o merge"
                : "DepGuard não encontrou problemas bloqueantes";
        String summary = String.format(
                "**%d** segredo(s) e **%d** vulnerabilidade(s) encontrados (%d CRITICAL/HIGH).",
                secretCount, vulnCount, criticalOrHigh);

        checkRunClient.patchCompleted(token, repoFullName, checkRunId, conclusion, title, summary);

        // Comentário é best-effort: se falhar (PR fechado, rate limit, etc.),
        // não pode sobrescrever o Check Run que já foi reportado corretamente
        // acima — esse é o sinal que de fato bloqueia/libera o merge.
        try {
            commentClient.postComment(token, repoFullName, prNumber,
                    "## DepGuard\n\n" + summary + "\n\nVeja detalhes na aba **Checks** deste PR.");
        } catch (Exception e) {
            log.warn("Check Run reportado (conclusion={}), mas falha ao comentar no PR #{} de {}",
                    conclusion, prNumber, repoFullName, e);
        }
    }
}
