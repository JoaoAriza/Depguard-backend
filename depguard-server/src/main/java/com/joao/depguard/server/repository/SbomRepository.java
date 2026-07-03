package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Sbom;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface SbomRepository extends JpaRepository<Sbom, UUID> {
}
