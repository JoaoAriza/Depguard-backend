package com.joao.depguard.core.report;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.joao.depguard.core.model.ScanResult;

/** Serializa o {@link ScanResult} bruto como JSON (formato interno, não normatizado). */
public class JsonReportWriter {

    private final ObjectMapper mapper;

    public JsonReportWriter() {
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    public String write(ScanResult result) {
        try {
            return mapper.writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Falha ao serializar ScanResult", e);
        }
    }
}
