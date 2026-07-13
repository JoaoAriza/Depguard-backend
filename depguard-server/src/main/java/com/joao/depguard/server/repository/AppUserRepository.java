package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AppUserRepository extends JpaRepository<AppUser, UUID> {

    Optional<AppUser> findByEmail(String email);

    boolean existsByEmail(String email);

    List<AppUser> findByOrganizationOrderByNameAsc(Organization organization);
}
