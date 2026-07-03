package com.joao.depguard.server.service;

import com.joao.depguard.server.dto.ApiKeyDto;
import com.joao.depguard.server.model.ApiKey;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Organization;
import com.joao.depguard.server.repository.ApiKeyRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Fork do {@code ApiKeyService} do CyberAudit, SEM o gate de Plan/billing
 * (Account/Plan não existem no MVP do DepGuard — ver docs/architecture.md).
 * Qualquer usuário ativo da organização pode criar/gerenciar suas keys.
 */
@Service
public class ApiKeyService {

    private static final String PREFIX = "dg_";
    private static final int MAX_KEYS_PER_ORG = 10;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ApiKeyRepository apiKeyRepository;
    private final PasswordEncoder passwordEncoder;

    public ApiKeyService(ApiKeyRepository apiKeyRepository, PasswordEncoder passwordEncoder) {
        this.apiKeyRepository = apiKeyRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public List<ApiKeyDto> list(AppUser user) {
        return apiKeyRepository.findByOrganizationOrderByCreatedAtDesc(user.getOrganization())
                .stream().map(ApiKeyDto::from).toList();
    }

    @Transactional
    public ApiKeyDto create(String name, AppUser user) {
        Organization organization = user.getOrganization();

        long activeCount = apiKeyRepository.findByOrganizationOrderByCreatedAtDesc(organization)
                .stream().filter(ApiKey::isActive).count();
        if (activeCount >= MAX_KEYS_PER_ORG) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Limite de " + MAX_KEYS_PER_ORG + " API keys ativas atingido.");
        }

        if (name == null || name.isBlank() || name.length() > 100) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Nome da API key inválido (máx. 100 caracteres).");
        }
        if (apiKeyRepository.existsByOrganizationAndName(organization, name.trim())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Já existe uma API key com este nome.");
        }

        byte[] raw = new byte[16];
        RANDOM.nextBytes(raw);
        String hex = HexFormat.of().formatHex(raw); // 32 hex chars
        String plainKey = PREFIX + hex;              // dg_<32>
        String keyPrefix = plainKey.substring(0, Math.min(11, plainKey.length()));

        ApiKey key = ApiKey.builder()
                .name(name.trim())
                .keyPrefix(keyPrefix)
                .keyHash(passwordEncoder.encode(plainKey))
                .organization(organization)
                .createdBy(user)
                .createdAt(LocalDateTime.now())
                .build();

        ApiKey saved = apiKeyRepository.save(key);

        ApiKeyDto dto = ApiKeyDto.from(saved);
        dto.setPlainKey(plainKey); // único momento em que a chave completa é retornada
        return dto;
    }

    @Transactional
    public void revoke(UUID keyId, AppUser user) {
        ApiKey key = apiKeyRepository.findById(keyId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "API key não encontrada."));

        if (!key.getOrganization().getId().equals(user.getOrganization().getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Sem permissão para esta API key.");
        }
        if (key.getRevokedAt() != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "API key já revogada.");
        }

        key.setRevokedAt(LocalDateTime.now());
        apiKeyRepository.save(key);
    }

    /** Usado pelo {@code ApiKeyAuthFilter}. Vazio se a key for inválida, expirada ou revogada. */
    public Optional<AppUser> validate(String rawKey) {
        if (rawKey == null || !rawKey.startsWith(PREFIX) || rawKey.length() < 11) {
            return Optional.empty();
        }
        String prefix = rawKey.substring(0, Math.min(11, rawKey.length()));

        List<ApiKey> candidates = apiKeyRepository.findByKeyPrefixAndRevokedAtIsNull(prefix);
        for (ApiKey k : candidates) {
            if (!k.isActive()) {
                continue;
            }
            if (passwordEncoder.matches(rawKey, k.getKeyHash())) {
                k.setLastUsedAt(LocalDateTime.now());
                apiKeyRepository.save(k);
                return Optional.of(k.getCreatedBy());
            }
        }
        return Optional.empty();
    }
}
