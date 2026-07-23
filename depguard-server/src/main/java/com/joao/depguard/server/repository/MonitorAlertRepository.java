package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.MonitorAlert;
import com.joao.depguard.server.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface MonitorAlertRepository extends JpaRepository<MonitorAlert, UUID> {

    /** Todos os alertas do projeto — usado na reconciliação (mapa por fingerprint). */
    List<MonitorAlert> findByProject(Project project);

    /** Listagem para a UI (§7, 3d): mais recentes primeiro. */
    List<MonitorAlert> findByProjectOrderByDetectedAtDesc(Project project);
}
