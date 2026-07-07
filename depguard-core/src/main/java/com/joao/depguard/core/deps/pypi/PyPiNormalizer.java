package com.joao.depguard.core.deps.pypi;

import java.util.regex.Pattern;

/**
 * Normalização de nome de pacote PyPI (PEP 503): minúsculo, runs de
 * {@code -_.} viram um único hífen. Necessário porque "Foo_Bar" e "foo-bar"
 * são o MESMO pacote no PyPI — sem normalizar, o mesmo componente apareceria
 * como dois diferentes vindo de poetry.lock vs. requirements.txt.
 */
public final class PyPiNormalizer {

    private static final Pattern SEPARATORS = Pattern.compile("[-_.]+");

    private PyPiNormalizer() {
    }

    public static String normalize(String name) {
        return SEPARATORS.matcher(name.toLowerCase()).replaceAll("-");
    }
}
