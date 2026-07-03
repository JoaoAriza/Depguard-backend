package com.joao.depguard.server.config;

import com.joao.depguard.server.security.ApiKeyAuthFilter;
import com.joao.depguard.server.security.JwtAuthFilter;
import com.joao.depguard.server.security.JwtUtil;
import com.joao.depguard.server.security.UserDetailsServiceImpl;
import com.joao.depguard.server.service.ApiKeyService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Fork simplificado do SecurityConfig do CyberAudit: sem as dezenas de rotas
 * específicas do scanner de sites — só o essencial pro MVP (auth pública,
 * resto autenticado).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsServiceImpl;
    private final ApiKeyService apiKeyService;
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(JwtUtil jwtUtil,
                           UserDetailsServiceImpl userDetailsServiceImpl,
                           ApiKeyService apiKeyService,
                           PasswordEncoder passwordEncoder) {
        this.jwtUtil = jwtUtil;
        this.userDetailsServiceImpl = userDetailsServiceImpl;
        this.apiKeyService = apiKeyService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * @Bean sem @Component nos filtros: evita registro automático como
     * servlet filter (dupla execução), mesmo cuidado do CyberAudit.
     */
    @Bean
    public JwtAuthFilter jwtAuthFilter() {
        return new JwtAuthFilter(jwtUtil, userDetailsServiceImpl);
    }

    @Bean
    public ApiKeyAuthFilter apiKeyAuthFilter() {
        return new ApiKeyAuthFilter(apiKeyService);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        // defesa extra: exceções não tratadas por GlobalExceptionHandler
                        // ainda cairiam no forward padrão do Boot para /error
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                // ApiKeyAuthFilter antes do JWT — X-Api-Key é processado primeiro
                .addFilterBefore(apiKeyAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsServiceImpl);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
