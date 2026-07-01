package com.joao.depguard.core.secrets;

import com.joao.depguard.core.model.Allowlist;

import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/** Aplica a {@link Allowlist}: paths (glob), regex de valor, ou fingerprint específico. */
public class AllowlistMatcher {

    private final List<PathMatcher> pathMatchers;
    private final List<Pattern> valuePatterns;
    private final Allowlist allowlist;

    public AllowlistMatcher(Allowlist allowlist) {
        this.allowlist = allowlist;
        this.pathMatchers = new ArrayList<>();
        for (String glob : allowlist.paths()) {
            this.pathMatchers.add(FileSystems.getDefault().getPathMatcher("glob:" + glob));
        }
        this.valuePatterns = new ArrayList<>();
        for (String regex : allowlist.valueRegexes()) {
            this.valuePatterns.add(Pattern.compile(regex));
        }
    }

    public boolean isAllowlistedPath(Path relativePath) {
        for (PathMatcher m : pathMatchers) {
            if (m.matches(relativePath)) {
                return true;
            }
        }
        return false;
    }

    public boolean isAllowlistedValue(String value) {
        for (Pattern p : valuePatterns) {
            if (p.matcher(value).find()) {
                return true;
            }
        }
        return false;
    }

    public boolean isAllowlistedFingerprint(String fingerprint) {
        return allowlist.fingerprints().contains(fingerprint);
    }
}
