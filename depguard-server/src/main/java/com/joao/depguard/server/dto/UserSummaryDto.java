package com.joao.depguard.server.dto;

import com.joao.depguard.server.model.AppUser;

import java.util.UUID;

public record UserSummaryDto(UUID id, String name, String email) {

    public static UserSummaryDto from(AppUser user) {
        return new UserSummaryDto(user.getId(), user.getName(), user.getEmail());
    }
}
