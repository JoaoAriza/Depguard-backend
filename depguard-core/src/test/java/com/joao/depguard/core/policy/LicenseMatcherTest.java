package com.joao.depguard.core.policy;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class LicenseMatcherTest {

    @Test
    void casaPadraoComCuringa() {
        assertThat(LicenseMatcher.isDenied("GPL-3.0", Set.of("GPL-*"))).isTrue();
        assertThat(LicenseMatcher.isDenied("GPL-2.0", Set.of("GPL-*"))).isTrue();
    }

    /**
     * O caso que quebraria com "contains": AGPL é uma licença DIFERENTE de
     * GPL. É por isso que o doc lista GPL-* e AGPL-* separadamente.
     */
    @Test
    void gplNaoCasaComAgplPorqueOCasamentoEhAncorado() {
        assertThat(LicenseMatcher.isDenied("AGPL-3.0", Set.of("GPL-*"))).isFalse();
        assertThat(LicenseMatcher.isDenied("LGPL-2.1", Set.of("GPL-*"))).isFalse();

        // e casam quando o padrão certo é usado
        assertThat(LicenseMatcher.isDenied("AGPL-3.0", Set.of("AGPL-*"))).isTrue();
    }

    @Test
    void casaExatoSemCuringa() {
        assertThat(LicenseMatcher.isDenied("MIT", Set.of("MIT"))).isTrue();
        assertThat(LicenseMatcher.isDenied("MIT", Set.of("APACHE-2.0"))).isFalse();
    }

    @Test
    void ehInsensivelAMaiusculas() {
        assertThat(LicenseMatcher.isDenied("gpl-3.0", Set.of("GPL-*"))).isTrue();
        assertThat(LicenseMatcher.isDenied("GPL-3.0", Set.of("gpl-*"))).isTrue();
    }

    @Test
    void expressaoSpdxCompostaDisparaPorQualquerTermo() {
        assertThat(LicenseMatcher.isDenied("(MIT OR GPL-3.0)", Set.of("GPL-*"))).isTrue();
        assertThat(LicenseMatcher.isDenied("MIT AND GPL-2.0", Set.of("GPL-*"))).isTrue();
        // sem termo de risco: não dispara
        assertThat(LicenseMatcher.isDenied("(MIT OR Apache-2.0)", Set.of("GPL-*"))).isFalse();
    }

    @Test
    void licencaVaziaOuSemPadraoNaoDispara() {
        assertThat(LicenseMatcher.isDenied(null, Set.of("GPL-*"))).isFalse();
        assertThat(LicenseMatcher.isDenied("", Set.of("GPL-*"))).isFalse();
        assertThat(LicenseMatcher.isDenied("GPL-3.0", Set.of())).isFalse();
    }

    /** Ponto do SPDX é literal, não curinga de regex. */
    @Test
    void pontoNaoEhTratadoComoCuringaDeRegex() {
        assertThat(LicenseMatcher.isDenied("GPLX3X0", Set.of("GPL-3.0"))).isFalse();
    }
}
