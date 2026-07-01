package com.joao.depguard.core.secrets;

import java.util.HashMap;
import java.util.Map;

/** Entropia de Shannon, usada para achar segredos genéricos sem padrão conhecido. */
public final class ShannonEntropy {

    private ShannonEntropy() {
    }

    public static double of(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }
        double len = s.length();
        double entropy = 0.0;
        for (int count : freq.values()) {
            double p = count / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
