package com.joao.depguard.core.secrets.verify;

import com.joao.depguard.core.model.VerificationStatus;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Orquestra a verificação ao vivo de um scan: roteia cada segredo pro
 * verificador que sabe checá-lo e deduplica por hash (o mesmo segredo achado
 * em vários arquivos é verificado uma vez só).
 *
 * <p><b>Uma instância por scan</b> — o cache é intencionalmente de vida curta:
 * um token revogado entre dois scans não pode aparecer como VERIFIED por causa
 * de cache velho. O cache guarda só o STATUS (por hash), nunca o valor cru.
 */
public final class SecretVerification {

    private final List<SecretVerifier> verifiers;
    private final boolean enabled;
    private final Map<String, VerificationStatus> cacheByHash = new HashMap<>();

    private SecretVerification(List<SecretVerifier> verifiers, boolean enabled) {
        this.verifiers = verifiers;
        this.enabled = enabled;
    }

    /** Opt-in desligado: tudo fica NOT_CHECKED, nenhuma chamada de rede. */
    public static SecretVerification disabled() {
        return new SecretVerification(List.of(), false);
    }

    /** Verificadores padrão (só GitHub hoje — ver docs §3.3). */
    public static SecretVerification withDefaults() {
        return new SecretVerification(List.of(new GithubTokenVerifier()), true);
    }

    /** Injeção de verificadores (usado em teste com fakes, sem tocar a rede). */
    public static SecretVerification of(List<SecretVerifier> verifiers) {
        return new SecretVerification(verifiers, true);
    }

    /**
     * @param rawValue usado só aqui dentro, nunca guardado — some quando o
     *                 chamador (que também não o retém) sai de escopo.
     */
    public VerificationStatus verify(String ruleId, String secretHash, String rawValue) {
        if (!enabled) {
            return VerificationStatus.NOT_CHECKED;
        }
        VerificationStatus cached = cacheByHash.get(secretHash);
        if (cached != null) {
            return cached;
        }
        VerificationStatus status = VerificationStatus.NOT_CHECKED;
        for (SecretVerifier verifier : verifiers) {
            if (verifier.supports(ruleId)) {
                status = verifier.verify(rawValue);
                break;
            }
        }
        cacheByHash.put(secretHash, status);
        return status;
    }
}
