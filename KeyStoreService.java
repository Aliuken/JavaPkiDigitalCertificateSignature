package com.aliuken.pki.service;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import com.aliuken.pki.model.CertificateData;

public class KeyStoreService {
	public CertificateData getCertificateDataFromJavaKeyStore() {
		try {
			String keyStoreType = "PKCS12";
			String certificateFilePath = "C:\\OpenSSL-Win64\\bin\\my_certificate.pfx";
			String certificateFilePassword = "my_password";

			KeyStore javaKeyStore = KeyStore.getInstance(keyStoreType);
			try(InputStream inputStream = new FileInputStream(certificateFilePath)) {
				javaKeyStore.load(inputStream, certificateFilePassword.toCharArray());
			}

			String jksAlias = javaKeyStore.aliases().nextElement();

			PrivateKey privateKey = (PrivateKey) javaKeyStore.getKey(jksAlias, certificateFilePassword.toCharArray());
			Certificate[] certificateChain = javaKeyStore.getCertificateChain(jksAlias);
			X509Certificate publicCertificate = (X509Certificate) certificateChain[0];
			String subjectAlias = publicCertificate.getSubjectX500Principal().getName();

			CertificateData certificateData = new CertificateData(privateKey, certificateChain, publicCertificate, subjectAlias);
			return certificateData;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public List<CertificateData> getCertificateDataListFromWindowsKeyStore() {
		try {
			String keyStoreType = "Windows-MY";
			String providerName = "SunMSCAPI";

			KeyStore windowsKeyStore = KeyStore.getInstance(keyStoreType, providerName);
			windowsKeyStore.load(null, null);

			Enumeration<String> wksAliases = windowsKeyStore.aliases();

			List<CertificateData> certificateDataList = new ArrayList<>();
			while (wksAliases.hasMoreElements()) {
				String wksAlias = wksAliases.nextElement();

				PrivateKey privateKey = (PrivateKey) windowsKeyStore.getKey(wksAlias, null);
				Certificate[] certificateChain = windowsKeyStore.getCertificateChain(wksAlias);
				X509Certificate publicCertificate = (X509Certificate) certificateChain[0];
				String subjectAlias = publicCertificate.getSubjectX500Principal().getName();

				CertificateData certificateData = new CertificateData(privateKey, certificateChain, publicCertificate, subjectAlias);
				certificateDataList.add(certificateData);
			}
			return certificateDataList;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
