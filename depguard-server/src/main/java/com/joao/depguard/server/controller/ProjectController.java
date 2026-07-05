package com.joao.depguard.server.controller;

import com.joao.depguard.server.dto.CreateProjectRequest;
import com.joao.depguard.server.dto.ProjectDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.service.ProjectService;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/projects")
public class ProjectController {

    private final ProjectService projectService;

    public ProjectController(ProjectService projectService) {
        this.projectService = projectService;
    }

    @GetMapping
    public List<ProjectDto> list(@AuthenticationPrincipal AppUser user) {
        return projectService.list(user).stream().map(ProjectDto::from).toList();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ProjectDto create(@RequestBody CreateProjectRequest req, @AuthenticationPrincipal AppUser user) {
        return ProjectDto.from(projectService.create(req, user));
    }
}
