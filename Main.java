package com.aliuken.pki;

import com.aliuken.pki.model.CertificateData;
import com.aliuken.pki.service.KeyStoreService;
import com.aliuken.pki.service.PdfSignatureService;
import com.aliuken.pki.service.SignatureService;
import com.aliuken.pki.service.XmlSignatureService;

import java.util.List;

public class Main {
    public static void main(String[] args) {
        KeyStoreService keyStoreService = new KeyStoreService();
        List<CertificateData> certificateDataList = keyStoreService.getCertificateDataListFromWindowsKeyStore();
        if(certificateDataList != null) {
        	int i = 1;
        	for(CertificateData certificateData : certificateDataList) {
        		try {
	        		SignatureService signatureService = new PdfSignatureService();
	                boolean result = signatureService.sign(certificateData, "C:\\documents\\test.pdf", "C:\\documents\\test_signed" + i + ".pdf");
	                
	                if(result) {
		                signatureService = new XmlSignatureService();
		                result = signatureService.sign(certificateData, "C:\\documents\\test.xml", "C:\\documents\\test_signed" + i + ".xml");
	                }
	                
	                if(result) {
	                	i++;
	                } else {
	                	System.out.println("pdf and xml not signed");
	                }
        		} catch(Exception e) {
        			System.out.println("pdf and xml not signed because of exception: " + e.getMessage());
        		}
        	}
        }
    }
}
