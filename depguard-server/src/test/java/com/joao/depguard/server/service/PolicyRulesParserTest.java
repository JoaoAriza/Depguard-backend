package com.joao.depguard.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.core.policy.PolicyRules;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PolicyRulesParserTest {

    private final PolicyRulesParser parser = new PolicyRulesParser();
    private final ObjectMapper mapper = new ObjectMapper();

    private PolicyRules parse(String json) throws Exception {
        return parser.parse(mapper.readTree(json));
    }

    @Test
    void objetoVazioHerdaTodosOsDefaults() throws Exception {
        assertThat(parse("{}")).isEqualTo(PolicyRules.defaults());
    }

    @Test
    void rulesNuloOuNaoObjetoCaiNosDefaults() {
        assertThat(parser.parse(null)).isEqualTo(PolicyRules.defaults());
        assertThat(parser.parse(mapper.nullNode())).isEqualTo(PolicyRules.defaults());
        assertThat(parser.parse(mapper.valueToTree("texto"))).isEqualTo(PolicyRules.defaults());
    }

    @Test
    void leTodosOsCamposQuandoInformados() throws Exception {
        PolicyRules r = parse("""
                {"failOnSecrets": false, "failOnSeverity": "CRITICAL",
                 "failOnKev": true, "failOnEpssAbove": 0.7}
                """);

        assertThat(r.failOnSecrets()).isFalse();
        assertThat(r.failOnSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(r.failOnKev()).isTrue();
        assertThat(r.failOnEpssAbove()).isEqualTo(0.7);
    }

    /**
     * A distinção que importa: ausente = "não opinei" (herda default);
     * null explícito = "desliga essa regra".
     */
    @Test
    void severidadeAusenteHerdaDefaultMasNullExplicitoDesligaARegra() throws Exception {
        assertThat(parse("{\"failOnKev\": true}").failOnSeverity())
                .isEqualTo(PolicyRules.defaults().failOnSeverity());

        assertThat(parse("{\"failOnSeverity\": null}").failOnSeverity()).isNull();
    }

    @Test
    void epssAusenteHerdaDefaultMasNullExplicitoDesligaARegra() throws Exception {
        assertThat(parse("{}").failOnEpssAbove()).isEqualTo(PolicyRules.defaults().failOnEpssAbove());
        assertThat(parse("{\"failOnEpssAbove\": null}").failOnEpssAbove()).isNull();
    }

    @Test
    void severidadeAceitaMinusculas() throws Exception {
        assertThat(parse("{\"failOnSeverity\": \"critical\"}").failOnSeverity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void severidadeInvalidaFalhaComMensagemClara() {
        assertThatThrownBy(() -> parse("{\"failOnSeverity\": \"URGENTE\"}"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("URGENTE")
                .hasMessageContaining("CRITICAL");
    }

    @Test
    void epssForaDoIntervaloZeroUmFalha() {
        assertThatThrownBy(() -> parse("{\"failOnEpssAbove\": 1.5}"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("entre 0 e 1");
        assertThatThrownBy(() -> parse("{\"failOnEpssAbove\": -0.1}"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("entre 0 e 1");
    }

    @Test
    void tipoErradoFalhaEmVezDeSerIgnoradoSilenciosamente() {
        assertThatThrownBy(() -> parse("{\"failOnSecrets\": \"sim\"}"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("true ou false");
        assertThatThrownBy(() -> parse("{\"failOnEpssAbove\": \"alto\"}"))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("número");
    }
}
