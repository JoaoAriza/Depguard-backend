package com.joao.depguard.server.github;

import com.joao.depguard.core.model.Engine;
import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.model.Finding;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.repository.FindingRepository;
import com.joao.depguard.server.repository.ScanRepository;
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

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final ScanExecutionService scanExecutionService;
    private final GithubRepoCloner repoCloner;
    private final GithubCheckRunClient checkRunClient;
    private final GithubPullRequestCommentClient commentClient;

    public GithubPullRequestScanRunner(ScanRepository scanRepository,
                                        FindingRepository findingRepository,
                                        ScanExecutionService scanExecutionService,
                                        GithubRepoCloner repoCloner,
                                        GithubCheckRunClient checkRunClient,
                                        GithubPullRequestCommentClient commentClient) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.scanExecutionService = scanExecutionService;
        this.repoCloner = repoCloner;
        this.checkRunClient = checkRunClient;
        this.commentClient = commentClient;
    }

    @Async
    public void runAsync(UUID scanId, String cloneUrl, String headSha, String token,
                          String repoFullName, long checkRunId, int prNumber) {
        Path clonedRepo = null;
        try {
            clonedRepo = repoCloner.cloneAtCommit(cloneUrl, headSha, token);
            boolean success = scanExecutionService.runSync(
                    scanId, clonedRepo, Set.of(Engine.DEPENDENCIES, Engine.SECRETS));

            if (!success) {
                checkRunClient.patchCompleted(token, repoFullName, checkRunId, "failure",
                        "DepGuard: erro ao escanear",
                        "O scan não terminou corretamente. Veja os logs do servidor.");
                return;
            }

            Scan scan = scanRepository.findById(scanId).orElseThrow();
            List<Finding> findings = findingRepository.findByScan(scan);
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
     */
    private void report(String token, String repoFullName, long checkRunId, int prNumber, List<Finding> findings) {
        long secretCount = findings.stream().filter(f -> f.getType() == FindingType.SECRET).count();
        long vulnCount = findings.stream().filter(f -> f.getType() == FindingType.DEPENDENCY_VULN).count();
        long criticalOrHigh = findings.stream()
                .filter(f -> f.getType() == FindingType.DEPENDENCY_VULN)
                .filter(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH)
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
