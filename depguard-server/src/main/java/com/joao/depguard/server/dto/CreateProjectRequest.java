package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.ProjectProvider;

public record CreateProjectRequest(
        String name,
        String repoUrl,
        ProjectProvider provider,
        String defaultBranch,
        /** Opcional: webhook de notificação de CVE-novo (§7, 3c). */
        String notificationWebhookUrl
) {}
