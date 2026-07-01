package com.joao.depguard.core.util;

import com.joao.depguard.core.model.BumpType;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SemVerTest {

    @Test
    void comparaVersoes() {
        assertThat(SemVer.parse("4.17.21")).isGreaterThan(SemVer.parse("4.17.20"));
        assertThat(SemVer.parse("2.0.0")).isGreaterThan(SemVer.parse("1.9.9"));
        assertThat(SemVer.parse("1.2.3")).isEqualByComparingTo(SemVer.parse("1.2.3"));
    }

    @Test
    void ignoraPrereleaseEBuild() {
        assertThat(SemVer.parse("1.2.3-beta.1")).isEqualByComparingTo(SemVer.parse("1.2.3"));
        assertThat(SemVer.parse("v1.2.3+build.7")).isEqualByComparingTo(SemVer.parse("1.2.3"));
    }

    @Test
    void classificaBump() {
        assertThat(SemVer.classifyBump("4.17.20", "4.17.21")).isEqualTo(BumpType.PATCH);
        assertThat(SemVer.classifyBump("4.17.20", "4.18.0")).isEqualTo(BumpType.MINOR);
        assertThat(SemVer.classifyBump("4.17.20", "5.0.0")).isEqualTo(BumpType.MAJOR);
        assertThat(SemVer.classifyBump("4.17.20", null)).isEqualTo(BumpType.NONE);
        assertThat(SemVer.classifyBump("4.17.21", "4.17.20")).isEqualTo(BumpType.NONE);
    }
}
