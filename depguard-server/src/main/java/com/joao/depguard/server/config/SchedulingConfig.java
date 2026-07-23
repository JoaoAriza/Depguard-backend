package com.joao.depguard.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Habilita os jobs {@code @Scheduled} (monitoramento contínuo, §7). Bean
 * separado do {@link AsyncConfig} só por clareza — poderiam coexistir na mesma
 * classe, mas manter uma anotação por arquivo deixa explícito o que cada
 * capacidade liga.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig {
}
