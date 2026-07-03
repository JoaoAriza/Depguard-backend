package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.ProjectProvider;

import java.time.LocalDateTime;
import java.util.UUID;

public record ProjectDto(
        UUID id, String name, String repoUrl, ProjectProvider provider,
        String defaultBranch, LocalDateTime createdAt
) {
    public static ProjectDto from(Project p) {
        return new ProjectDto(p.getId(), p.getName(), p.getRepoUrl(), p.getProvider(),
                p.getDefaultBranch(), p.getCreatedAt());
    }
}
