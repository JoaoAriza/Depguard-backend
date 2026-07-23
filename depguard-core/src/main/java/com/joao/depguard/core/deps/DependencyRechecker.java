package com.joao.depguard.core.deps;

import com.joao.depguard.core.deps.epss.EpssApi;
import com.joao.depguard.core.deps.epss.EpssClient;
import com.joao.depguard.core.deps.kev.KevApi;
import com.joao.depguard.core.deps.kev.KevClient;
import com.joao.depguard.core.deps.osv.OsvApi;
import com.joao.depguard.core.deps.osv.OsvClient;
import com.joao.depguard.core.deps.osv.OsvVulnerabilityScanner;
import com.joao.depguard.core.deps.priority.ExploitabilityEnricher;
import com.joao.depguard.core.model.Component;
import com.joao.depguard.core.model.VulnFinding;

import java.util.List;

/**
 * Re-corre <b>só a etapa OSV</b> (+ enriquecimento EPSS/KEV opcional) sobre uma
 * lista de componentes <b>já resolvidos</b> — sem clonar repo, sem parsear
 * lockfile. É a peça central do monitoramento contínuo (docs/architecture.md
 * §7): dada a lista de dependências que um projeto shipou (persistida em
 * {@code scan_components}), descobrir se o OSV passou a conhecer alguma
 * vulnerabilidade nova.
 *
 * <p>Extraído do {@link com.joao.depguard.core.DefaultScanner} de propósito:
 * o scan real e o re-check do monitor compartilham exatamente este mesmo
 * caminho, então um {@link VulnFinding} do monitor tem o mesmo
 * {@code fingerprint} e o mesmo enriquecimento que o scan original teria — é
 * o que torna a comparação "CVE novo vs. estado anterior" válida.
 */
public class DependencyRechecker {

    private final OsvApi osvApi;
    private final EpssApi epssApi;
    private final KevApi kevApi;

    public DependencyRechecker() {
        this(new OsvClient(), new EpssClient(), new KevClient());
    }

    /** Permite injetar APIs fake em testes, sem tocar a rede. */
    public DependencyRechecker(OsvApi osvApi, EpssApi epssApi, KevApi kevApi) {
        this.osvApi = osvApi;
        this.epssApi = epssApi;
        this.kevApi = kevApi;
    }

    /**
     * @param components componentes já resolvidos (ecossistema/nome/versão/purl)
     * @param enrich     se true, preenche {@code epssScore}/{@code kevListed}
     *                   (uma chamada extra a EPSS/KEV; ver §2.4)
     * @return vulnerabilidades atuais segundo o OSV para esses componentes
     */
    public List<VulnFinding> recheck(List<Component> components, boolean enrich) {
        if (components.isEmpty()) {
            return List.of();
        }
        List<VulnFinding> findings = new OsvVulnerabilityScanner(osvApi).scan(components);
        if (enrich && !findings.isEmpty()) {
            findings = new ExploitabilityEnricher(epssApi, kevApi).enrich(findings);
        }
        return findings;
    }
}
