package com.joao.depguard.core.testsupport;

/**
 * Fixtures de teste com o FORMATO de credenciais reais, mas que nunca são
 * credenciais válidas.
 *
 * <p>Construídas por concatenação de propósito: um scanner de segredo (o
 * nosso, ou o push-protection do GitHub) casa contra o texto bruto do
 * arquivo-fonte. Se o valor aparecesse como um literal contíguo, o próprio
 * repositório do DepGuard seria bloqueado ao publicar seus testes — o que
 * já aconteceu (ver commit que motivou esta classe). Em tempo de execução o
 * valor concatenado é idêntico, então os testes continuam exercitando as
 * mesmas regras de detecção.
 */
public final class FakeSecrets {

    private FakeSecrets() {
    }

    /** Bate no padrão de AWS Access Key ID (AKIA + 16 alfanuméricos), mas é fake. */
    public static final String AWS_ACCESS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP";
}
