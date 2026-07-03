package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Role;

import java.util.UUID;

public record UserDto(UUID id, String name, String email, Role role, UUID organizationId) {

    public static UserDto from(AppUser user) {
        return new UserDto(
                user.getId(), user.getName(), user.getEmail(),
                user.getRole(), user.getOrganization().getId());
    }
}
