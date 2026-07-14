package com.joao.depguard.core.secrets;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fixtures de patch abaixo são o formato REAL devolvido por
 * GET /repos/{owner}/{repo}/pulls/{number}/files (confirmado contra a API
 * do GitHub — octocat/Hello-World#10463 e microsoft/vscode#316277 — antes de
 * escrever o parser, não assumido de memória).
 */
class DiffPatchParserTest {

    @Test
    void arquivoNovoTemTodasAsLinhasComoAdicionadasAPartirDaLinha1() {
        String patch = "@@ -0,0 +1,3 @@\n+# Hello World\n+\n+Hello World!";

        List<DiffPatchParser.AddedLine> added = DiffPatchParser.addedLines(patch);

        assertThat(added).extracting(DiffPatchParser.AddedLine::lineNumber).containsExactly(1, 2, 3);
        assertThat(added).extracting(DiffPatchParser.AddedLine::text)
                .containsExactly("# Hello World", "", "Hello World!");
    }

    @Test
    void arquivoRemovidoNaoTemLinhasAdicionadas() {
        String patch = "@@ -1 +0,0 @@\n-Hello World!";

        assertThat(DiffPatchParser.addedLines(patch)).isEmpty();
    }

    @Test
    void modificacaoSoContaLinhasAdicionadasComNumeroCorretoIgnorandoContextoERemocao() {
        // hunk real: linhas de contexto (espaço) e duas adicionadas no meio do arquivo
        String patch = "@@ -4614,3 +4614,5 @@\n"
                + "               \"onExp\"\n"
                + "             ]\n"
                + "           },\n"
                + "+          \"nova.config\": {\n"
                + "+            \"type\": \"boolean\"\n";

        List<DiffPatchParser.AddedLine> added = DiffPatchParser.addedLines(patch);

        assertThat(added).extracting(DiffPatchParser.AddedLine::lineNumber).containsExactly(4617, 4618);
    }

    @Test
    void linhaRemovidaNaoAvancaContadorDeLinhaNova() {
        String patch = "@@ -1,2 +1,2 @@\n"
                + "-linha antiga\n"
                + "+linha nova\n"
                + " contexto";

        List<DiffPatchParser.AddedLine> added = DiffPatchParser.addedLines(patch);

        assertThat(added).containsExactly(new DiffPatchParser.AddedLine(1, "linha nova"));
    }

    @Test
    void patchNuloOuVazioNaoQuebra() {
        assertThat(DiffPatchParser.addedLines(null)).isEmpty();
        assertThat(DiffPatchParser.addedLines("")).isEmpty();
    }
}
