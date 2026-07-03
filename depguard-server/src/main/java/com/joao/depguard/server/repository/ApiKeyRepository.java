package com.joao.depguard.server.repository;

import com.joao.depguard.server.model.ApiKey;
import com.joao.depguard.server.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    List<ApiKey> findByOrganizationOrderByCreatedAtDesc(Organization organization);

    boolean existsByOrganizationAndName(Organization organization, String name);

    /**
     * Filtra candidatos pelo prefixo antes do BCrypt (evita full-table scan com hashes).
     *
     * <p>JOIN FETCH em {@code createdBy}/{@code organization} é necessário: quem chama
     * este método é o {@code ApiKeyAuthFilter}, um servlet filter que roda ANTES do
     * Open Session In View entrar em ação (OSIV só cobre a fase do DispatcherServlet
     * em diante). Sem o fetch, o AppUser retornado é um proxy Hibernate que já não
     * consegue mais ser inicializado — confirmado com {@code LazyInitializationException:
     * no Session} ao chamar {@code getAuthorities()} no filtro.
     */
    @Query("""
            SELECT k FROM ApiKey k
            JOIN FETCH k.createdBy u
            JOIN FETCH u.organization
            WHERE k.keyPrefix = :keyPrefix AND k.revokedAt IS NULL
            """)
    List<ApiKey> findByKeyPrefixAndRevokedAtIsNull(@Param("keyPrefix") String keyPrefix);
}
