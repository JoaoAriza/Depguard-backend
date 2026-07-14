package com.joao.depguard.core.secrets;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser mínimo de diff unificado, no formato exato devolvido pelo campo
 * {@code patch} de {@code GET /repos/{owner}/{repo}/pulls/{number}/files} do
 * GitHub (confirmado contra a API real — sem cabeçalho {@code --- a/}/
 * {@code +++ b/}, começa direto no hunk). Extrai só as linhas ADICIONADAS,
 * com o número de linha correto no arquivo NOVO — pra não reacusar segredo
 * que já existia antes do PR.
 */
public class DiffPatchParser {

    private static final Pattern HUNK_HEADER = Pattern.compile("^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,\\d+)? @@");

    public record AddedLine(int lineNumber, String text) {}

    public static List<AddedLine> addedLines(String patch) {
        List<AddedLine> result = new ArrayList<>();
        if (patch == null || patch.isBlank()) {
            return result;
        }

        int newLine = 0;
        for (String rawLine : patch.split("\n", -1)) {
            Matcher hunk = HUNK_HEADER.matcher(rawLine);
            if (hunk.find()) {
                newLine = Integer.parseInt(hunk.group(1));
                continue;
            }
            if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
                result.add(new AddedLine(newLine, rawLine.substring(1)));
                newLine++;
            } else if (rawLine.startsWith(" ")) {
                newLine++;
            }
            // linhas "-..." (removidas) e "\ No newline at end of file" não avançam newLine
        }
        return result;
    }
}
