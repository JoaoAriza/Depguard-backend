package com.joao.depguard.core.secrets;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ShannonEntropyTest {

    @Test
    void stringRepetitivaTemEntropiaBaixa() {
        assertThat(ShannonEntropy.of("aaaaaaaaaaaaaaaaaaaa")).isLessThan(1.0);
    }

    @Test
    void stringAleatoriaTemEntropiaAlta() {
        assertThat(ShannonEntropy.of("aK9$mZ2!pL0x@7wQvR3n")).isGreaterThan(3.5);
    }

    @Test
    void vazioTemEntropiaZero() {
        assertThat(ShannonEntropy.of("")).isZero();
    }
}
