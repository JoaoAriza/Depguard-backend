package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Organization;
import com.joao.depguard.server.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ProjectRepository extends JpaRepository<Project, UUID> {

    List<Project> findByOrganizationOrderByCreatedAtDesc(Organization organization);

    /** Correlaciona um evento de webhook do GitHub (repository.html_url) a um Project existente. */
    Optional<Project> findByRepoUrl(String repoUrl);
}
