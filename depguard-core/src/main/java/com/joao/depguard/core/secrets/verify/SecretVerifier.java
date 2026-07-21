package com.joao.depguard.core.secrets.verify;

import com.joao.depguard.core.model.VerificationStatus;

/**
 * Verifica ao vivo se um segredo detectado é uma credencial ATIVA
 * (docs/architecture.md §3.3, Fase 2, opt-in).
 *
 * <p><b>Segurança por construção:</b> cada verificador só fala com o provedor
 * LEGÍTIMO do seu tipo de segredo (o do GitHub só chama api.github.com). O
 * valor cru nunca vai pra um endpoint arbitrário — a implementação hardcoda
 * o destino, não recebe URL de fora.
 *
 * <p>O valor cru é usado só em memória, nunca retornado nem guardado — o
 * chamador descarta na hora (o core nunca persiste o segredo cru, §0).
 */
public interface SecretVerifier {

    /** true se este verificador sabe checar segredos desta regra. */
    boolean supports(String ruleId);

    /**
     * @return VERIFIED (credencial ativa), UNVERIFIED (checada e inválida), ou
     *         NOT_CHECKED se NÃO foi possível determinar (rede, rate-limit,
     *         timeout). Nunca reporta UNVERIFIED quando na dúvida — isso
     *         deixaria uma credencial viva passar como inofensiva.
     */
    VerificationStatus verify(String rawValue);
}
