package com.joao.depguard.core.secrets;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretMaskingTest {

    @Test
    void mascaraValorLongoMostraSoAsPontas() {
        assertThat(SecretMasking.mask("AKIAABCDEFGHIJKLMNOP")).isEqualTo("AKIA…MNOP");
    }

    @Test
    void mascaraValorCurtoComAsteriscos() {
        assertThat(SecretMasking.mask("abc")).isEqualTo("***");
    }
}
