package com.joao.depguard.server.security;

import com.joao.depguard.server.model.AppUser;
import com.joao.depguard.server.service.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Roda DEPOIS da autenticação (JWT/API key) para saber o {@code Role} do
 * usuário, mas se aplica a TODA requisição — inclusive {@code /auth/**},
 * que é público mas é justamente a superfície mais exposta a abuso
 * (brute-force de login, spam de registro): ali cai no caminho anônimo
 * (por IP), já que nenhuma autenticação acontece antes deste filtro.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;

    public RateLimitFilter(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {

        boolean allowed = rateLimitService.allow(request.getRemoteAddr(), currentUser());

        if (!allowed) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"status\":429,\"error\":\"Muitas requisições. Tente novamente em instantes.\"}");
            return;
        }

        chain.doFilter(request, response);
    }

    private AppUser currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof AppUser user) {
            return user;
        }
        return null;
    }
}
