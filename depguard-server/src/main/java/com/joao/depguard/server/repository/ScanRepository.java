package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Scan;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {
}
