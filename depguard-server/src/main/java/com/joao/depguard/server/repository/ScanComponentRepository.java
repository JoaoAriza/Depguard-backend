package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.ScanComponent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface ScanComponentRepository extends JpaRepository<ScanComponent, UUID> {
}
