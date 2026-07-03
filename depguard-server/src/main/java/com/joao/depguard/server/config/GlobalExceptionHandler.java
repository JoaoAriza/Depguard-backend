package com.joao.depguard.server.config;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;

/**
 * Escreve o corpo do erro diretamente, sem depender do redirecionamento
 * padrão do Spring Boot para {@code /error}.
 *
 * <p>Sem isso, uma {@link ResponseStatusException} lançada de um service
 * (ex.: CONFLICT no auto-registro) dispara o forward interno para
 * {@code /error}; como esse path não está liberado no SecurityConfig, o
 * Spring Security barra o forward com 403 vazio, mascarando o status/mensagem
 * reais — confirmado testando o endpoint /auth/register com email duplicado.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(ResponseStatusException e) {
        HttpStatusCode status = e.getStatusCode();
        return ResponseEntity.status(status).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", e.getReason() != null ? e.getReason() : status.toString()
        ));
    }
}
