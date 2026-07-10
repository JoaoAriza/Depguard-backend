package com.joao.depguard.server.github;

import com.fasterxml.jackson.databind.JsonNode;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.ScanTrigger;
import com.joao.depguard.server.repository.ProjectRepository;
import com.joao.depguard.server.service.ScanService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Parte SÍNCRONA do fluxo de webhook: acha o Project, cria o Check Run
 * "in_progress" (feedback rápido pro PR) e a linha do Scan. O trabalho
 * pesado (clonar + escanear) fica em {@link GithubPullRequestScanRunner},
 * um bean SEPARADO — {@code @Async} só funciona através do proxy do Spring,
 * então precisa ser uma chamada entre beans diferentes (mesmo motivo de
 * {@code ScanService}/{@code ScanExecutionService} no Passo 6d).
 */
@Service
public class GithubPullRequestWebhookHandler {

    private static final Logger log = LoggerFactory.getLogger(GithubPullRequestWebhookHandler.class);
    private static final Set<String> HANDLED_ACTIONS = Set.of("opened", "synchronize", "reopened");

    private final ProjectRepository projectRepository;
    private final ScanService scanService;
    private final GithubInstallationTokenClient tokenClient;
    private final GithubCheckRunClient checkRunClient;
    private final GithubPullRequestScanRunner scanRunner;

    public GithubPullRequestWebhookHandler(ProjectRepository projectRepository,
                                            ScanService scanService,
                                            GithubInstallationTokenClient tokenClient,
                                            GithubCheckRunClient checkRunClient,
                                            GithubPullRequestScanRunner scanRunner) {
        this.projectRepository = projectRepository;
        this.scanService = scanService;
        this.tokenClient = tokenClient;
        this.checkRunClient = checkRunClient;
        this.scanRunner = scanRunner;
    }

    public void handlePullRequestEvent(JsonNode payload) {
        String action = text(payload, "action");
        if (!HANDLED_ACTIONS.contains(action)) {
            return; // ex.: "closed", "assigned" — não nos interessam
        }

        JsonNode repository = payload.get("repository");
        String repoUrl = text(repository, "html_url");
        Optional<Project> maybeProject = projectRepository.findByRepoUrl(repoUrl);
        if (maybeProject.isEmpty()) {
            log.info("Webhook de PR pra repo sem Project cadastrado, ignorando: {}", repoUrl);
            return;
        }
        Project project = maybeProject.get();

        long installationId = payload.get("installation").get("id").asLong();
        if (project.getGithubInstallationId() == null || project.getGithubInstallationId() != installationId) {
            project.setGithubInstallationId(installationId);
            projectRepository.save(project);
        }

        JsonNode pullRequest = payload.get("pull_request");
        String headSha = text(pullRequest.get("head"), "sha");
        int prNumber = pullRequest.get("number").asInt();
        String repoFullName = text(repository, "full_name");
        String cloneUrl = text(repository, "clone_url");

        String token = tokenClient.createInstallationToken(installationId);
        long checkRunId = checkRunClient.createInProgress(token, repoFullName, headSha, "DepGuard");
        UUID scanId = scanService.createQueued(project, ScanTrigger.WEBHOOK);

        scanRunner.runAsync(scanId, cloneUrl, headSha, token, repoFullName, checkRunId, prNumber);
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null ? value.asText() : null;
    }
}
