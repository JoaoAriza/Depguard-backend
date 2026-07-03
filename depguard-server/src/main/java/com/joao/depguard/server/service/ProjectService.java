package com.joao.depguard.server.service;

import com.joao.depguard.server.dto.CreateProjectRequest;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.repository.ProjectRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class ProjectService {

    private final ProjectRepository projectRepository;

    public ProjectService(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }

    @Transactional
    public Project create(CreateProjectRequest req, AppUser user) {
        if (req.name() == null || req.name().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nome do projeto é obrigatório.");
        }
        Project project = Project.builder()
                .organization(user.getOrganization())
                .name(req.name().trim())
                .repoUrl(req.repoUrl())
                .provider(req.provider())
                .defaultBranch(req.defaultBranch())
                .createdAt(LocalDateTime.now())
                .build();
        return projectRepository.save(project);
    }

    public List<Project> list(AppUser user) {
        return projectRepository.findByOrganizationOrderByCreatedAtDesc(user.getOrganization());
    }
}
