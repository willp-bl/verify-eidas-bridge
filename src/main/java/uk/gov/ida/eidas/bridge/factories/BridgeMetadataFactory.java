package uk.gov.ida.eidas.bridge.factories;

import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.eidas.bridge.helpers.BridgeMetadataGenerator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.eidas.bridge.resources.BridgeMetadataResource;
import uk.gov.ida.saml.serializers.XmlObjectToElementTransformer;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public class BridgeMetadataFactory {

    private final String hostname;
    private final java.security.cert.Certificate signingCertificate, encryptingCertificate;
    private final PrivateKey privateKey;
    private final String entityId;

    public BridgeMetadataFactory(String hostname,
                                 java.security.cert.Certificate signingCertificate,
                                 java.security.cert.Certificate encryptingCertificate,
                                 PrivateKey privateKey, String entityId) {
        this.hostname = hostname;
        this.signingCertificate = signingCertificate;
        this.encryptingCertificate = encryptingCertificate;
        this.entityId = entityId;
        this.privateKey = privateKey;
    }

    public BridgeMetadataResource getBridgeMetadataResource() throws CertificateEncodingException {
        return new BridgeMetadataResource(getBridgeMetadataGenerator(), new XmlObjectToElementTransformer<>());
    }

    public BridgeMetadataGenerator getBridgeMetadataGenerator() throws CertificateEncodingException {
        Certificate verifyCertificate = getSigningCertificate();

        BasicCredential basicSigningCredential = new BasicCredential(this.signingCertificate.getPublicKey(), privateKey);
        BasicX509Credential x509Credential = new BasicX509Credential((X509Certificate) this.signingCertificate);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        return new BridgeMetadataGenerator(
            hostname,
            entityId,
            verifyCertificate,
            getEncryptingCertificate(),
            new SigningHelper(basicSigningCredential, x509Credential, keyInfoGenerator));
    }

    private Certificate getSigningCertificate() throws CertificateEncodingException {
        return new Certificate(entityId, encodeBase64String(signingCertificate.getEncoded()), Certificate.KeyUse.Signing);
    }

    private Certificate getEncryptingCertificate() throws CertificateEncodingException {
        return new Certificate(entityId, encodeBase64String(encryptingCertificate.getEncoded()), Certificate.KeyUse.Encryption);
    }
}
