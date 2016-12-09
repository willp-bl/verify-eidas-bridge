package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.joda.time.Hours;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.transformers.KeyDescriptorsUnmarshaller;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.singletonList;

public class BridgeMetadataGenerator {


    private final String hostname;
    private final String entityId;
    private final KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller;
    private final Certificate signingCertificate, encryptingCertificate;
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private final KeyInfoGenerator keyInfoGenerator;
    private final BasicCredential basicSigningCredential;
    private final X509Credential x509SigningCredential;


    public BridgeMetadataGenerator(
        String hostname, String entityId,
        KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller,
        Certificate signingCertificate,
        Certificate encryptingCertificate,
        KeyInfoGenerator keyInfoGenerator,
        BasicCredential signingCredential,
        X509Credential x509SigningCredential) {
        this.hostname = hostname;
        this.entityId = entityId;
        this.keyDescriptorsUnmarshaller = keyDescriptorsUnmarshaller;
        this.signingCertificate = signingCertificate;
        this.encryptingCertificate = encryptingCertificate;
        this.keyInfoGenerator = keyInfoGenerator;
        this.basicSigningCredential = signingCredential;
        this.x509SigningCredential = x509SigningCredential;
    }

    public EntitiesDescriptor generateMetadata() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = new EntitiesDescriptorBuilder().buildObject();
        entitiesDescriptor.setID("entitiesDescriptor");
        entitiesDescriptor.setValidUntil(new DateTime().plus(Hours.ONE));

        final EntityDescriptor bridgeEntityDescriptor = createEntityDescriptor(entityId);

        entitiesDescriptor.getEntityDescriptors().add(bridgeEntityDescriptor);
        signObject(entitiesDescriptor);

        return entitiesDescriptor;
    }

    private void signObject(SignableXMLObject xmlObject) throws MarshallingException, SignatureException, SecurityException {
        Signature signature = openSamlXmlObjectFactory.createSignature();
        signature.setKeyInfo(keyInfoGenerator.generate(x509SigningCredential));
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        signature.setSigningCredential(basicSigningCredential);
        xmlObject.setSignature(signature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject).marshall(xmlObject);
        Signer.signObject(signature);
    }

    private EntityDescriptor createEntityDescriptor(String entityId) throws MarshallingException, SecurityException, SignatureException {
        XMLObjectBuilderFactory openSamlBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        EntityDescriptor entityDescriptor = (EntityDescriptor) openSamlBuilderFactory.getBuilder(EntityDescriptor.TYPE_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME, EntityDescriptor.TYPE_NAME);
        entityDescriptor.setEntityID(entityId);
        entityDescriptor.getRoleDescriptors().add(getSpSsoDescriptor(openSamlXmlObjectFactory));
        entityDescriptor.setID("bridgeEntityDescriptor");

        signObject(entityDescriptor);
        return entityDescriptor;
    }

    private RoleDescriptor getSpSsoDescriptor(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) throws SignatureException, MarshallingException, SecurityException {
        SPSSODescriptor spSsoDescriptor = openSamlXmlObjectFactory.createSPSSODescriptor();
        spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        List<Certificate> signingAndEncryptionCerts = new ArrayList<>();
        signingAndEncryptionCerts.add(signingCertificate);
        signingAndEncryptionCerts.add(encryptingCertificate);
        spSsoDescriptor.getKeyDescriptors().addAll(keyDescriptorsUnmarshaller.fromCertificates(signingAndEncryptionCerts));
        spSsoDescriptor.setID("spSsoDescriptor");
        AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
        assertionConsumerService.setLocation(hostname + EidasResponseResource.ASSERTION_CONSUMER_PATH);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        spSsoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);
        signObject(spSsoDescriptor);
        return spSsoDescriptor;
    }
}
