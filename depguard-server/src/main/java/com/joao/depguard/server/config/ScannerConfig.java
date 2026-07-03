package com.joao.depguard.server.config;

import com.joao.depguard.core.DefaultScanner;
import com.joao.depguard.core.Scanner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@code DefaultScanner} vive no core (sem Spring de propósito — ver
 * docs/architecture.md §0). Só o Bean wiring fica no server.
 */
@Configuration
public class ScannerConfig {

    @Bean
    public Scanner scanner() {
        return new DefaultScanner();
    }
}
