package uk.gov.ida.eidas.bridge.factories;

import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.eidas.bridge.helpers.BridgeMetadataGenerator;
import uk.gov.ida.eidas.bridge.resources.BridgeMetadataResource;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.transformers.KeyDescriptorsUnmarshaller;
import uk.gov.ida.saml.serializers.XmlObjectToElementTransformer;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.apache.commons.codec.binary.Base64.encodeBase64String;

public class BridgeMetadataFactory {

    private final String hostname;
    private final java.security.cert.Certificate certificate;
    private final PrivateKey privateKey;
    private final String entityId;

    public BridgeMetadataFactory(String hostname, java.security.cert.Certificate certificate, PrivateKey privateKey, String entityId) {
        this.hostname = hostname;
        this.certificate = certificate;
        this.entityId = entityId;
        this.privateKey = privateKey;
    }

    public BridgeMetadataResource getBridgeMetadataResource() throws KeyStoreException, CertificateEncodingException, UnrecoverableKeyException, NoSuchAlgorithmException {
        return new BridgeMetadataResource(getBridgeMetadataGenerator(), new XmlObjectToElementTransformer<>());
    }

    public BridgeMetadataGenerator getBridgeMetadataGenerator() throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller = new KeyDescriptorsUnmarshaller(new OpenSamlXmlObjectFactory());
        Certificate signingCertificate = getSigningCertificate();

        BasicCredential basicSigningCredential = new BasicCredential(certificate.getPublicKey(), privateKey);
        BasicX509Credential x509Credential = new BasicX509Credential((X509Certificate) certificate);

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        return new BridgeMetadataGenerator(
            hostname,
            entityId,
            keyDescriptorsUnmarshaller,
            signingCertificate,
            keyInfoGenerator,
            basicSigningCredential,
            x509Credential);
    }

    private Certificate getSigningCertificate() throws KeyStoreException, CertificateEncodingException {
        return new Certificate(entityId, encodeBase64String(certificate.getEncoded()), Certificate.KeyUse.Signing);
    }
}
