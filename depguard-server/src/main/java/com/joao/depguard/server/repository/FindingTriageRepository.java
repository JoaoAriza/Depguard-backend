package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.FindingTriage;
import com.joao.depguard.server.model.Project;
import com.joao.depguard.server.model.TriageStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FindingTriageRepository extends JpaRepository<FindingTriage, UUID> {

    Optional<FindingTriage> findByProjectAndFingerprint(Project project, String fingerprint);

    List<FindingTriage> findByProjectAndFingerprintIn(Project project, List<String> fingerprints);

    List<FindingTriage> findByProjectAndStatus(Project project, TriageStatus status);

    /** Triagens do projeto em qualquer um dos status — ex.: suprimir alerta de FALSE_POSITIVE/ACCEPTED_RISK. */
    List<FindingTriage> findByProjectAndStatusIn(Project project, Collection<TriageStatus> statuses);
}
