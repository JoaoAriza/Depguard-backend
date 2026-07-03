package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.ProjectProvider;

public record CreateProjectRequest(
        String name,
        String repoUrl,
        ProjectProvider provider,
        String defaultBranch
) {}
