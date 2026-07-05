package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanComponent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ScanComponentRepository extends JpaRepository<ScanComponent, UUID> {

    List<ScanComponent> findByScan(Scan scan);
}
