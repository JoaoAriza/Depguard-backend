package com.joao.depguard.server.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "projects")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Project {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "organization_id", nullable = false)
    private Organization organization;

    @Column(nullable = false)
    private String name;

    /** Nulo para projetos escaneados só via CLI local (provider LOCAL). */
    private String repoUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ProjectProvider provider;

    private String defaultBranch;

    /**
     * ID da instalação do GitHub App (não do App em si) que dá acesso a este
     * repositório — preenchido no primeiro webhook recebido para ele.
     * Necessário pra trocar o JWT do App por um token de instalação (a
     * credencial usada pra chamar a API do GitHub em nome do repositório).
     */
    private Long githubInstallationId;

    /**
     * URL de webhook para notificações de CVE-novo do monitoramento contínuo
     * (§7, 3c). Null/vazio = cai no fallback global
     * ({@code depguard.notifications.webhook-url}) ou fica desabilitado.
     */
    private String notificationWebhookUrl;

    @Column(nullable = false)
    private LocalDateTime createdAt;
}
