package com.joao.depguard.core.secrets;

import com.joao.depguard.core.testsupport.FakeSecrets;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretMaskingTest {

    @Test
    void mascaraValorLongoMostraSoAsPontas() {
        assertThat(SecretMasking.mask(FakeSecrets.AWS_ACCESS_KEY)).isEqualTo("AKIA…MNOP");
    }

    @Test
    void mascaraValorCurtoComAsteriscos() {
        assertThat(SecretMasking.mask("abc")).isEqualTo("***");
    }
}
