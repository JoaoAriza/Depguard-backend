package com.joao.depguard.server.report;

import com.joao.depguard.core.model.FindingType;
import com.joao.depguard.core.model.Severity;
import com.joao.depguard.server.dto.FindingDto;
import com.joao.depguard.server.model.Scan;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Fork simplificado do {@code PdfReportService} do CyberAudit (mesma
 * abordagem: PDFBox de baixo nível, sem HTML intermediário — ver
 * docs/architecture.md §0.3). Uma única seção de findings (vs. as ~20 do
 * CyberAudit), mas reaproveita o mesmo kit de helpers de desenho/paginação.
 */
@Service
public class PdfReportService {

    private static final float M = 45f;
    private static final float LH = 13f;
    private static final float PH = PDRectangle.A4.getHeight();
    private static final float PW = PDRectangle.A4.getWidth();
    private static final float CW = PW - 2 * M;

    private static final float[] NAVY = {0.05f, 0.08f, 0.12f};
    private static final float[] DARK = {0.09f, 0.13f, 0.19f};
    private static final float[] ACCENT = {0f, 0.83f, 0.63f};
    private static final float[] WHITE = {1f, 1f, 1f};
    private static final float[] TEXT = {0.12f, 0.16f, 0.22f};
    private static final float[] MUTED = {0.42f, 0.50f, 0.58f};
    private static final float[] BORDER = {0.86f, 0.89f, 0.92f};
    private static final float[] BGLIGHT = {0.96f, 0.97f, 0.98f};
    private static final float[] CRIT = {0.84f, 0.10f, 0.10f};
    private static final float[] HIGH = {0.89f, 0.40f, 0.05f};
    private static final float[] MED = {0.76f, 0.52f, 0.04f};
    private static final float[] LOW_C = {0.18f, 0.44f, 0.76f};
    private static final float[] INFO_C = {0.44f, 0.53f, 0.62f};

    private PDDocument doc;
    private PDPageContentStream cs;
    private float cy;
    private int pageNo;
    private PDType1Font bold, normal, mono;

    public byte[] generate(Scan scan, List<FindingDto> findings) {
        try {
            doc = new PDDocument();
            bold = PDType1Font.HELVETICA_BOLD;
            normal = PDType1Font.HELVETICA;
            mono = PDType1Font.COURIER;
            pageNo = 0;
            cs = null;

            openPage();
            coverHeader(scan);
            summaryBox(scan, findings);

            List<FindingDto> vulns = findings.stream().filter(f -> f.type() == FindingType.DEPENDENCY_VULN).toList();
            List<FindingDto> secrets = findings.stream().filter(f -> f.type() == FindingType.SECRET).toList();

            if (!vulns.isEmpty()) findingsSection("Dependências vulneráveis", vulns);
            if (!secrets.isEmpty()) findingsSection("Segredos", secrets);
            if (vulns.isEmpty() && secrets.isEmpty()) noFindingsNote();

            closePage();

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            doc.close();
            return out.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao gerar PDF: " + e.getMessage(), e);
        }
    }

    // ── Page management ──────────────────────────────────────────────────

    private void openPage() throws IOException {
        PDPage page = new PDPage(PDRectangle.A4);
        doc.addPage(page);
        cs = new PDPageContentStream(doc, page);
        pageNo++;
        cy = PH - M;
    }

    private void closePage() throws IOException {
        fill(M, 28, CW, 0.5f, BORDER);
        txt("DepGuard Security Report  —  Confidential", M, 18, normal, 7, MUTED);
        txtR("Page " + pageNo, PW - M, 18, normal, 7, MUTED);
        cs.close();
    }

    private void need(float h) throws IOException {
        if (cy - h < 55) {
            closePage();
            openPage();
        }
    }

    // ── Cover / summary ──────────────────────────────────────────────────

    private void coverHeader(Scan scan) throws IOException {
        fill(0, PH - 85, PW, 85, NAVY);
        fill(0, PH - 85, 4, 85, ACCENT);

        txt("DEPGUARD", M + 8, PH - 34, bold, 22, ACCENT);
        txt(scan.getProject().getName(), M + 8, PH - 52, normal, 11, WHITE);

        String date = scan.getFinishedAt() != null
                ? scan.getFinishedAt().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"))
                : "—";
        txtR("Scan: " + date, PW - M, PH - 38, normal, 8, MUTED);
        txtR("CONFIDENTIAL", PW - M, PH - 52, bold, 7, MUTED);
        cy = PH - 100;
    }

    private void summaryBox(Scan scan, List<FindingDto> findings) throws IOException {
        Map<Severity, Long> bySeverity = findings.stream()
                .filter(f -> f.severity() != null)
                .collect(java.util.stream.Collectors.groupingBy(FindingDto::severity, java.util.stream.Collectors.counting()));

        float boxH = 60;
        fill(M, cy - boxH, CW, boxH, BGLIGHT);
        strokeRect(M, cy - boxH, CW, boxH, BORDER);
        fill(M, cy - boxH, 3, boxH, ACCENT);

        txt("SCAN", M + 12, cy - 12, bold, 7, MUTED);
        txt(scan.getId().toString(), M + 12, cy - 24, mono, 8, TEXT);
        txt("STATUS", M + 12, cy - 40, bold, 7, MUTED);
        txt(scan.getStatus().name() + (scan.isPartial() ? " (parcial)" : ""), M + 12, cy - 52, normal, 9, TEXT);

        txtR(findings.size() + " finding(s)", PW - M - 12, cy - 24, bold, 11, TEXT);
        cy -= boxH + 12;

        long total = bySeverity.values().stream().mapToLong(Long::longValue).sum();
        if (total > 0) {
            txt("SEVERITY DISTRIBUTION", M, cy - 2, bold, 7, MUTED);
            cy -= 13;
            float bx = M, bh = 9;
            fill(bx, cy - bh, CW, bh, BORDER);
            for (Severity sev : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
                long n = bySeverity.getOrDefault(sev, 0L);
                if (n == 0) continue;
                float w = CW * n / total;
                fill(bx, cy - bh, w, bh, sevColor(sev));
                bx += w;
            }
            cy -= 13;
            bx = M;
            for (Severity sev : new Severity[]{Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO}) {
                long n = bySeverity.getOrDefault(sev, 0L);
                if (n == 0) continue;
                String label = sev.name() + " " + n;
                fill(bx, cy - 6, 7, 7, sevColor(sev));
                txt(label, bx + 11, cy, normal, 8, MUTED);
                bx += 11 + sw(label, normal, 8) + 14;
            }
            cy -= 14;
        }
        cy -= 10;
    }

    private void noFindingsNote() throws IOException {
        need(20);
        txt("Nenhum finding neste scan.", M, cy, normal, 10, MUTED);
        cy -= LH;
    }

    // ── Findings section ─────────────────────────────────────────────────

    private void findingsSection(String title, List<FindingDto> findings) throws IOException {
        need(35);
        cy -= 10;
        fill(M, cy - 18, CW, 18, DARK);
        fill(M, cy - 18, 3, 18, ACCENT);
        txt(title + " (" + findings.size() + ")", M + 10, cy - 13, bold, 9, WHITE);
        cy -= 30;

        List<FindingDto> sorted = findings.stream()
                .sorted((a, b) -> severityRank(a.severity()) - severityRank(b.severity()))
                .toList();
        for (FindingDto f : sorted) {
            findingRow(f);
        }
    }

    private void findingRow(FindingDto f) throws IOException {
        final float FBW = 58f;
        final float TX = M + 8 + FBW + 8;

        String description = describe(f);
        String triageLine = triageLine(f);

        float txtW = CW - (TX - M);
        int descLines = lineCount(description, bold, 9, txtW);
        int triageLines = triageLine != null ? lineCount(triageLine, normal, 8, txtW) : 0;
        int totalLines = 1 + descLines + (triageLines > 0 ? triageLines : 0);
        need(LH * totalLines + 14);

        String sevLabel = f.severity() != null ? f.severity().name() : "INFO";
        float[] sc = sevColor(f.severity());
        float[] sb = sevBg(f.severity());
        float startY = cy;

        fill(M + 8, cy - LH + 1, FBW, 11, sb);
        txt(sevLabel, M + 8 + (FBW - sw(sevLabel, bold, 7)) / 2f, cy - 2, bold, 7, sc);

        float lastY = wrapTxt(description, TX, cy, bold, 9, TEXT, txtW);
        cy = lastY - LH;

        if (triageLine != null) {
            lastY = wrapTxt(triageLine, TX, cy, normal, 8, MUTED, txtW);
            cy = lastY - LH;
        }

        fill(M, cy, 3, startY - cy + LH, sc);
        fill(M, cy - 1, CW, 0.3f, BORDER);
        cy -= 5;
    }

    private String describe(FindingDto f) {
        var d = f.detail();
        if (f.type() == FindingType.DEPENDENCY_VULN) {
            String purl = text(d, "affectedPurl");
            String id = firstAlias(d);
            String fixed = text(d, "fixedVersion");
            return purl + " — " + id + (fixed != null ? " (corrigido em " + fixed + ")" : "");
        }
        String ruleId = text(d, "ruleId");
        String path = text(d, "path");
        String line = d.has("lineStart") ? String.valueOf(d.get("lineStart").asInt()) : "?";
        return "Segredo (" + ruleId + ") em " + path + ":" + line;
    }

    private String triageLine(FindingDto f) {
        if (f.triageStatus() == null) return null;
        StringBuilder sb = new StringBuilder("Triagem: ").append(triageLabel(f.triageStatus()));
        if (f.triageAssigneeName() != null) sb.append(" — responsável: ").append(f.triageAssigneeName());
        if (f.triageNote() != null && !f.triageNote().isBlank()) sb.append(" — \"").append(f.triageNote()).append('"');
        return sb.toString();
    }

    private String triageLabel(com.joao.depguard.server.model.TriageStatus status) {
        return switch (status) {
            case OPEN -> "Aberto";
            case FALSE_POSITIVE -> "Falso positivo";
            case ACCEPTED_RISK -> "Risco aceito";
            case FIXED -> "Corrigido";
        };
    }

    private String text(com.fasterxml.jackson.databind.JsonNode node, String field) {
        var v = node.get(field);
        return v != null && !v.isNull() ? v.asText() : null;
    }

    private String firstAlias(com.fasterxml.jackson.databind.JsonNode d) {
        var aliases = d.get("aliases");
        if (aliases != null && aliases.isArray() && aliases.size() > 0) return aliases.get(0).asText();
        String osvId = text(d, "osvId");
        return osvId != null ? osvId : "—";
    }

    private int severityRank(Severity sev) {
        if (sev == null) return 5;
        return switch (sev) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case INFO -> 4;
        };
    }

    // ── Low-level drawing helpers (fork do CyberAudit) ──────────────────

    private void fill(float x, float y, float w, float h, float[] col) throws IOException {
        cs.setNonStrokingColor(new PDColor(col, PDDeviceRGB.INSTANCE));
        cs.addRect(x, y, w, h);
        cs.fill();
    }

    private void strokeRect(float x, float y, float w, float h, float[] col) throws IOException {
        cs.setStrokingColor(new PDColor(col, PDDeviceRGB.INSTANCE));
        cs.setLineWidth(0.5f);
        cs.addRect(x, y, w, h);
        cs.stroke();
    }

    private void txt(String str, float x, float y, PDType1Font f, float sz, float[] col) throws IOException {
        if (str == null || str.isBlank()) return;
        cs.beginText();
        cs.setNonStrokingColor(new PDColor(col, PDDeviceRGB.INSTANCE));
        cs.setFont(f, sz);
        cs.newLineAtOffset(x, y);
        cs.showText(clip(str, 110));
        cs.endText();
    }

    private void txtR(String str, float rightX, float y, PDType1Font f, float sz, float[] col) throws IOException {
        if (str == null || str.isBlank()) return;
        float w = sw(str, f, sz);
        txt(str, rightX - w, y, f, sz, col);
    }

    private float wrapTxt(String text, float x, float y, PDType1Font f, float sz, float[] col, float maxW) throws IOException {
        if (text == null || text.isBlank()) return y;
        String[] words = text.split("\\s+");
        StringBuilder line = new StringBuilder();
        float curY = y;
        for (String word : words) {
            String test = line.length() == 0 ? word : line + " " + word;
            if (sw(test, f, sz) > maxW && line.length() > 0) {
                txt(line.toString(), x, curY, f, sz, col);
                curY -= LH;
                line = new StringBuilder(word);
            } else {
                line = new StringBuilder(test);
            }
        }
        if (line.length() > 0) txt(line.toString(), x, curY, f, sz, col);
        return curY;
    }

    private int lineCount(String text, PDType1Font f, float sz, float maxW) {
        if (text == null || text.isBlank()) return 0;
        String[] words = text.split("\\s+");
        StringBuilder line = new StringBuilder();
        int count = 1;
        for (String word : words) {
            String test = line.length() == 0 ? word : line + " " + word;
            if (sw(test, f, sz) > maxW && line.length() > 0) {
                count++;
                line = new StringBuilder(word);
            } else {
                line = new StringBuilder(test);
            }
        }
        return count;
    }

    private float sw(String str, PDType1Font f, float sz) {
        if (str == null || str.isBlank()) return 0;
        try {
            return f.getStringWidth(str) / 1000f * sz;
        } catch (IOException e) {
            return str.length() * sz * 0.5f;
        }
    }

    private String clip(String str, int max) {
        return str.length() <= max ? str : str.substring(0, max - 3) + "...";
    }

    private float[] sevColor(Severity sev) {
        if (sev == null) return INFO_C;
        return switch (sev) {
            case CRITICAL -> CRIT;
            case HIGH -> HIGH;
            case MEDIUM -> MED;
            case LOW -> LOW_C;
            case INFO -> INFO_C;
        };
    }

    private float[] sevBg(Severity sev) {
        if (sev == null) return new float[]{0.92f, 0.93f, 0.94f};
        return switch (sev) {
            case CRITICAL -> new float[]{0.98f, 0.91f, 0.91f};
            case HIGH -> new float[]{0.99f, 0.94f, 0.89f};
            case MEDIUM -> new float[]{0.99f, 0.97f, 0.87f};
            case LOW -> new float[]{0.89f, 0.92f, 0.98f};
            case INFO -> new float[]{0.92f, 0.93f, 0.94f};
        };
    }
}
