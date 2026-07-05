package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Sbom;
import com.joao.depguard.server.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface SbomRepository extends JpaRepository<Sbom, UUID> {

    Optional<Sbom> findByScan(Scan scan);
}
