package com.joao.depguard.core.secrets;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PlaceholderFilterTest {

    @Test
    void reconhecePalavrasPlaceholder() {
        assertThat(PlaceholderFilter.isPlaceholder("changeme")).isTrue();
        assertThat(PlaceholderFilter.isPlaceholder("your-api-key-here")).isTrue();
        assertThat(PlaceholderFilter.isPlaceholder("example-secret-value")).isTrue();
    }

    @Test
    void reconheceStringRepetitiva() {
        assertThat(PlaceholderFilter.isPlaceholder("XXXXXXXXXXXXXXXX")).isTrue();
        assertThat(PlaceholderFilter.isPlaceholder("000000000000")).isTrue();
    }

    @Test
    void naoMarcaValorRealComoPlaceholder() {
        assertThat(PlaceholderFilter.isPlaceholder("aK9mZ2pL0xQvR3nB7cD1")).isFalse();
    }
}
