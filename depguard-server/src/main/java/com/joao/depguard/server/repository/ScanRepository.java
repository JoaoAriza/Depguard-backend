package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.Scan;
import com.joao.depguard.server.model.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {

    /**
     * Scan mais recente concluído do projeto — usado como o "estado atual"
     * de findings do projeto (docs/architecture.md §5). Snapshot simples
     * pro MVP; vira mais rico quando o monitoramento contínuo (§7 do doc)
     * existir.
     */
    Optional<Scan> findFirstByProjectAndStatusOrderByFinishedAtDesc(Project project, ScanStatus status);

    List<Scan> findByProjectOrderByCreatedAtDesc(Project project);
}
