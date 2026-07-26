package com.joao.depguard.server.dto;

/**
 * Define (ou limpa) o webhook de notificação de CVE-novo de um projeto (§7, 3c).
 * {@code webhookUrl} null/vazio remove o webhook do projeto (volta ao fallback
 * global ou desabilitado).
 */
public record UpdateNotificationRequest(String webhookUrl) {}
