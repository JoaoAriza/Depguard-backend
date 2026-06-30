package com.joao.depguard.core.model;

/**
 * Segredo detectado (Engine B).
 *
 * <p>NUNCA contém o segredo cru: apenas amostra mascarada e hash, conforme a
 * regra de dados sensíveis (docs/architecture.md §0).
 *
 * @param fingerprint         identidade estável entre scans (§4.1)
 * @param ruleId              regra que disparou (ex.: DG-SECRET-AWS)
 * @param path                caminho do arquivo
 * @param lineStart           primeira linha
 * @param lineEnd             última linha
 * @param commitSha           commit onde foi achado (null em working tree)
 * @param maskedSample        amostra mascarada (ex.: AKIA…XR4Q)
 * @param secretHash          sha256 do segredo (dedup/triage sem guardar o cru)
 * @param entropy             entropia de Shannon do valor
 * @param verificationStatus  resultado da verificação ao vivo
 * @param allowlisted         true se suprimido por allowlist
 */
public record SecretFinding(
        String fingerprint,
        String ruleId,
        String path,
        int lineStart,
        int lineEnd,
        String commitSha,
        String maskedSample,
        String secretHash,
        double entropy,
        VerificationStatus verificationStatus,
        boolean allowlisted
) {}
