package com.joao.depguard.core.secrets;

import java.util.regex.Pattern;

/**
 * Filtro de contexto: placeholders óbvios (docs/architecture.md §3.3),
 * ex.: {@code AKIAXXXXXXXXXXXXXXXX}, {@code sk_live_xxx}, {@code example}, {@code changeme}.
 */
public final class PlaceholderFilter {

    private static final Pattern PLACEHOLDER_WORD = Pattern.compile(
            "(?i)example|changeme|your[_-]?(api[_-]?)?key|placeholder|dummy|fake|test[_-]?secret");

    private PlaceholderFilter() {
    }

    private static final int MIN_REPEATED_RUN = 6;

    public static boolean isPlaceholder(String value) {
        if (value == null || value.isEmpty()) {
            return true;
        }
        if (PLACEHOLDER_WORD.matcher(value).find()) {
            return true;
        }
        // string quase toda repetitiva, ex.: 000000... / xxxxxxx
        long distinctChars = value.chars().distinct().count();
        if (distinctChars <= 2 && value.length() >= 6) {
            return true;
        }
        // corrida longa do mesmo caractere, ex.: AKIAXXXXXXXXXXXXXXXX
        return longestRun(value) >= MIN_REPEATED_RUN;
    }

    private static int longestRun(String value) {
        int longest = 1;
        int current = 1;
        for (int i = 1; i < value.length(); i++) {
            if (value.charAt(i) == value.charAt(i - 1)) {
                current++;
                longest = Math.max(longest, current);
            } else {
                current = 1;
            }
        }
        return longest;
    }
}
