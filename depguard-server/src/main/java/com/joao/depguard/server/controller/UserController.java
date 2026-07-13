package com.joao.depguard.server.controller;

import com.joao.depguard.server.dto.UserSummaryDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.repository.AppUserRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Só o necessário pro seletor de responsável na triagem (§ allowlist na UI) —
 * escopado pela organização do usuário autenticado, igual ProjectController.
 */
@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final AppUserRepository appUserRepository;

    public UserController(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @GetMapping
    public List<UserSummaryDto> list(@AuthenticationPrincipal AppUser user) {
        return appUserRepository.findByOrganizationOrderByNameAsc(user.getOrganization()).stream()
                .map(UserSummaryDto::from)
                .toList();
    }
}
