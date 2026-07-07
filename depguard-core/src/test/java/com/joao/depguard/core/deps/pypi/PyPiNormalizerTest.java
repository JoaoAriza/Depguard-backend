package com.joao.depguard.core.deps.pypi;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PyPiNormalizerTest {

    @Test
    void normalizaMaiusculasESeparadores() {
        assertThat(PyPiNormalizer.normalize("Foo_Bar")).isEqualTo("foo-bar");
        assertThat(PyPiNormalizer.normalize("Django")).isEqualTo("django");
        assertThat(PyPiNormalizer.normalize("zope.interface")).isEqualTo("zope-interface");
        assertThat(PyPiNormalizer.normalize("foo--bar__baz")).isEqualTo("foo-bar-baz");
    }
}
