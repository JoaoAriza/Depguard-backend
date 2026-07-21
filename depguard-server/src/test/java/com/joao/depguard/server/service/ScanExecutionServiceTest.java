package com.joao.depguard.server.service;

import com.joao.depguard.core.model.SecretScanMode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ScanExecutionServiceTest {

    /**
     * Propriedade de SEGURANÇA: o {@code .depguard.yml} do head de um PR NÃO é
     * respeitado — senão um contribuidor malicioso allowlistaria, no mesmo PR,
     * o segredo que está introduzindo. Checkout completo (código do dono) é
     * confiável.
     */
    @Test
    void prDiffNaoRespeitaConfigDoRepoMasCheckoutCompletoSim() {
        assertThat(ScanExecutionService.honorsRepoConfig(SecretScanMode.PR_DIFF)).isFalse();
        assertThat(ScanExecutionService.honorsRepoConfig(SecretScanMode.WORKING_TREE)).isTrue();
        assertThat(ScanExecutionService.honorsRepoConfig(SecretScanMode.GIT_HISTORY)).isTrue();
    }
}
