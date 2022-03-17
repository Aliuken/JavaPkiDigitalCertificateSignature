package com.udemy.pki.model;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public record CertificateData(PrivateKey privateKey, Certificate[] certificateChain, X509Certificate publicCertificate, String subjectAlias) {

}
