package com.aliuken.pki.reader;

import com.itextpdf.text.pdf.PdfReader;

import java.io.IOException;

public class AutocloseablePdfReader extends PdfReader implements AutoCloseable {
    public AutocloseablePdfReader(byte[] pdfIn) throws IOException {
        super(pdfIn);
    }
}
