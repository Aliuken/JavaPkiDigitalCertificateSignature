package com.aliuken.pki.service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

import com.aliuken.pki.model.CertificateData;
import org.xml.sax.SAXException;

public class XmlSignatureService implements SignatureService {
	@Override
	public void sign(CertificateData certificateData) {
		byte[] documentContent;
		try {
			Path path = Paths.get("C:\\documents\\test.xml");
			documentContent = Files.readAllBytes(path);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		byte[] signatureResult = this.sign(documentContent, certificateData);

		try(FileOutputStream out = new FileOutputStream("C:\\documents\\test_signed.xml")) {
			out.write(signatureResult);
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		System.out.println("xml signed");
	}

	@Override
	public byte[] sign(byte[] documentContent, CertificateData certificateData) {
		try {
			XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");
			Reference reference = XmlSignatureService.getReference(xmlSignatureFactory);
			SignedInfo signedInfo = XmlSignatureService.getSignedInfo(xmlSignatureFactory, reference);
			KeyInfo keyInfo = XmlSignatureService.getKeyInfo(xmlSignatureFactory, certificateData);
			Document document = XmlSignatureService.getDocument(documentContent);

	        DOMSignContext domSignContext = new DOMSignContext(certificateData.privateKey(), document.getDocumentElement());
	        domSignContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

	        XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, null, "signatureId", null);
	        xmlSignature.sign(domSignContext);

			byte[] newDocumentBytes = XmlSignatureService.getNewDocumentBytes(document);
	        return newDocumentBytes;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	private static Reference getReference(XMLSignatureFactory xmlSignatureFactory) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null);
		List<Transform> transforms = Collections.singletonList(xmlSignatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null));
		Reference reference = xmlSignatureFactory.newReference("", digestMethod, transforms,null,null);

		return reference;
	}

	private static SignedInfo getSignedInfo(XMLSignatureFactory xmlSignatureFactory, Reference reference) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
		CanonicalizationMethod canonicalizationMethod = xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
		//SignatureMethod signatureMethod = xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
		SignatureMethod signatureMethod = xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
		List<Reference> references = Collections.singletonList(reference);
		SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(canonicalizationMethod, signatureMethod, references);

		return signedInfo;
	}

	private static KeyInfo getKeyInfo(XMLSignatureFactory xmlSignatureFactory, CertificateData certificateData) {
		KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
		X509Certificate publicCertificate = certificateData.publicCertificate();

		List<Object> x509Content = new ArrayList<>();
		x509Content.add(publicCertificate.getSubjectX500Principal().getName());
		x509Content.add(publicCertificate);

		X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
		KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

		return keyInfo;
	}

	private static Document getDocument(byte[] data) throws ParserConfigurationException, IOException, SAXException {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);

		InputStream is = new ByteArrayInputStream(data);
		Document document = documentBuilderFactory.newDocumentBuilder().parse(is);

		return document;
	}

	private static byte[] getNewDocumentBytes(Document document) throws TransformerException {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();

		ByteArrayOutputStream newDocument = new ByteArrayOutputStream();
		transformer.transform(new DOMSource(document), new StreamResult(newDocument));

		byte[] newDocumentBytes = newDocument.toByteArray();

		return newDocumentBytes;
	}
}
