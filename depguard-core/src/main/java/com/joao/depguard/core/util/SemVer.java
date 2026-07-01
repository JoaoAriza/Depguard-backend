package com.joao.depguard.core.util;

import com.joao.depguard.core.model.BumpType;

/**
 * SemVer mínimo (major.minor.patch) para comparação de versões e classificação
 * do tipo de salto. Ignora prerelease/build — suficiente para escolher a menor
 * versão segura e rotular patch/minor/major (ver docs/architecture.md §2.3).
 */
public record SemVer(int major, int minor, int patch) implements Comparable<SemVer> {

    public static SemVer parse(String version) {
        String s = version.startsWith("v") ? version.substring(1) : version;
        int dash = s.indexOf('-');
        if (dash >= 0) {
            s = s.substring(0, dash);
        }
        int plus = s.indexOf('+');
        if (plus >= 0) {
            s = s.substring(0, plus);
        }
        String[] parts = s.split("\\.");
        return new SemVer(part(parts, 0), part(parts, 1), part(parts, 2));
    }

    private static int part(String[] parts, int idx) {
        if (idx >= parts.length) {
            return 0;
        }
        try {
            return Integer.parseInt(parts[idx].trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    @Override
    public int compareTo(SemVer o) {
        if (major != o.major) {
            return Integer.compare(major, o.major);
        }
        if (minor != o.minor) {
            return Integer.compare(minor, o.minor);
        }
        return Integer.compare(patch, o.patch);
    }

    /** Classifica o salto de {@code current} até {@code fixed}. */
    public static BumpType classifyBump(String current, String fixed) {
        if (fixed == null) {
            return BumpType.NONE;
        }
        SemVer cur = parse(current);
        SemVer fix = parse(fixed);
        if (fix.compareTo(cur) <= 0) {
            return BumpType.NONE; // já seguro ou "downgrade"
        }
        if (fix.major != cur.major) {
            return BumpType.MAJOR;
        }
        if (fix.minor != cur.minor) {
            return BumpType.MINOR;
        }
        return BumpType.PATCH;
    }
}
