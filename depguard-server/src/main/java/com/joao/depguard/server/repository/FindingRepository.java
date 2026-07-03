package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Finding;
import com.joao.depguard.server.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface FindingRepository extends JpaRepository<Finding, UUID> {

    List<Finding> findByScan(Scan scan);
}
