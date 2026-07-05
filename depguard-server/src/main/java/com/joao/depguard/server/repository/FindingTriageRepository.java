package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.FindingTriage;
import com.joao.depguard.server.model.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface FindingTriageRepository extends JpaRepository<FindingTriage, UUID> {

    Optional<FindingTriage> findByProjectAndFingerprint(Project project, String fingerprint);

    List<FindingTriage> findByProjectAndFingerprintIn(Project project, List<String> fingerprints);
}
