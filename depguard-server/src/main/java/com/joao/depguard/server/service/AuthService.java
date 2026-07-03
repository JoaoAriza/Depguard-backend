package com.joao.depguard.server.service;

import com.joao.depguard.server.dto.AuthResponse;
import com.joao.depguard.server.dto.LoginRequest;
import com.joao.depguard.server.dto.RegisterRequest;
import com.joao.depguard.server.dto.UserDto;
import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.model.Organization;
import com.joao.depguard.server.model.Role;
import com.joao.depguard.server.repository.AppUserRepository;
import com.joao.depguard.server.repository.OrganizationRepository;
import com.joao.depguard.server.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;

/**
 * Auth mínima do MVP: só register (auto-registro, cria Organization + AppUser
 * OWNER) e login. Sem 2FA, API keys ficam no Passo 6c.
 */
@Service
public class AuthService {

    private final AppUserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authManager;

    public AuthService(AppUserRepository userRepository,
                        OrganizationRepository organizationRepository,
                        PasswordEncoder passwordEncoder,
                        JwtUtil jwtUtil,
                        AuthenticationManager authManager) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authManager = authManager;
    }

    @Transactional
    public AuthResponse register(RegisterRequest req) {
        if (req.name() == null || req.name().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nome é obrigatório.");
        }
        if (req.organizationName() == null || req.organizationName().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Nome da organização é obrigatório.");
        }
        if (req.email() == null || req.email().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email é obrigatório.");
        }
        if (req.password() == null || req.password().length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Senha deve ter pelo menos 8 caracteres.");
        }

        String email = req.email().toLowerCase().trim();
        if (userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Email já cadastrado. Faça login ou use outro endereço.");
        }

        Organization org = Organization.builder()
                .name(req.organizationName().trim())
                .createdAt(LocalDateTime.now())
                .build();
        organizationRepository.save(org);

        AppUser user = AppUser.builder()
                .name(req.name().trim())
                .email(email)
                .passwordHash(passwordEncoder.encode(req.password()))
                .role(Role.OWNER)
                .active(true)
                .createdAt(LocalDateTime.now())
                .organization(org)
                .build();
        userRepository.save(user);

        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, UserDto.from(user));
    }

    public AuthResponse login(LoginRequest req) {
        String email = req.email() == null ? "" : req.email().toLowerCase().trim();

        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, req.password()));
        } catch (AuthenticationException e) {
            // Sem isso, a exceção escapa pro AuthenticationEntryPoint padrão do
            // Spring Security (Http403ForbiddenEntryPoint) e vira 403 — errado
            // pra credencial inválida, que é 401. Confirmado testando /auth/login.
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciais inválidas.");
        }

        AppUser user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Credenciais inválidas."));

        String token = jwtUtil.generateToken(user);
        return new AuthResponse(token, UserDto.from(user));
    }
}
