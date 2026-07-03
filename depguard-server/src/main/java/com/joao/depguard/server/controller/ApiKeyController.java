package com.joao.depguard.server.controller;

import com.joao.depguard.server.dto.ApiKeyDto;
import com.joao.depguard.server.dto.CreateApiKeyRequest;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.service.ApiKeyService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** CRUD de API keys. Só acessível via JWT (não faz sentido criar key com key). */
@RestController
@RequestMapping("/api-keys")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;

    public ApiKeyController(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @GetMapping
    public List<ApiKeyDto> list(@AuthenticationPrincipal AppUser user) {
        return apiKeyService.list(user);
    }

    @PostMapping
    public ApiKeyDto create(@RequestBody CreateApiKeyRequest req, @AuthenticationPrincipal AppUser user) {
        return apiKeyService.create(req.name(), user);
    }

    @DeleteMapping("/{id}")
    public void revoke(@PathVariable UUID id, @AuthenticationPrincipal AppUser user) {
        apiKeyService.revoke(id, user);
    }
}
