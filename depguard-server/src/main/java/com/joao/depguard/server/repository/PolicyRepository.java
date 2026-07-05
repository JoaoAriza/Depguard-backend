package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Policy;
import com.joao.depguard.server.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PolicyRepository extends JpaRepository<Policy, UUID> {

    Optional<Policy> findByProject(Project project);
}
