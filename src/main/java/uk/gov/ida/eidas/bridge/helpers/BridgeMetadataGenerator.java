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
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.AssertionConsumerServiceBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.KeyDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.SPSSODescriptorBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.KeyNameBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;

import java.util.List;

public class BridgeMetadataGenerator {


    private final String hostname;
    private final String entityId;
    private final Certificate signingCertificate;
    private final Certificate encryptingCertificate;
    private final SigningHelper signingHelper;


    public BridgeMetadataGenerator(
        String hostname, String entityId,
        Certificate signingCertificate,
        Certificate encryptingCertificate,
        SigningHelper signingHelper) {
        this.hostname = hostname;
        this.entityId = entityId;
        this.signingCertificate = signingCertificate;
        this.encryptingCertificate = encryptingCertificate;
        this.signingHelper = signingHelper;
    }

    public EntitiesDescriptor generateMetadata() throws SignatureException, MarshallingException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = new EntitiesDescriptorBuilder().buildObject();
        entitiesDescriptor.setID("entitiesDescriptor");
        entitiesDescriptor.setValidUntil(new DateTime().plus(Hours.ONE));

        final EntityDescriptor bridgeEntityDescriptor = createEntityDescriptor(entityId);

        entitiesDescriptor.getEntityDescriptors().add(bridgeEntityDescriptor);
        signingHelper.sign(entitiesDescriptor);

        return entitiesDescriptor;
    }

    private EntityDescriptor createEntityDescriptor(String entityId) throws MarshallingException, SecurityException, SignatureException {
        XMLObjectBuilderFactory openSamlBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        EntityDescriptor entityDescriptor = (EntityDescriptor) openSamlBuilderFactory.getBuilder(EntityDescriptor.TYPE_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME, EntityDescriptor.TYPE_NAME);
        entityDescriptor.setEntityID(entityId);
        entityDescriptor.getRoleDescriptors().add(getSpSsoDescriptor());
        entityDescriptor.setID("bridgeEntityDescriptor");

        signingHelper.sign(entityDescriptor);
        return entityDescriptor;
    }

    private RoleDescriptor getSpSsoDescriptor() throws SignatureException, MarshallingException, SecurityException {
        SPSSODescriptor spSsoDescriptor = new SPSSODescriptorBuilder().buildObject();
        spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        List<KeyDescriptor> keyDescriptors = spSsoDescriptor.getKeyDescriptors();
        keyDescriptors.add(fromCertificate(signingCertificate));
        keyDescriptors.add(fromCertificate(encryptingCertificate));
        spSsoDescriptor.setID("spSsoDescriptor");
        AssertionConsumerService assertionConsumerService = new AssertionConsumerServiceBuilder().buildObject();
        assertionConsumerService.setLocation(hostname + EidasResponseResource.ASSERTION_CONSUMER_PATH);
        assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        spSsoDescriptor.getAssertionConsumerServices().add(assertionConsumerService);
        signingHelper.sign(spSsoDescriptor);
        return spSsoDescriptor;
    }

    private KeyDescriptor fromCertificate(Certificate certificateDto) {

        KeyName keyName = new KeyNameBuilder().buildObject();
        keyName.setValue(certificateDto.getIssuerId());

        X509Certificate x509Certificate = new X509CertificateBuilder().buildObject();
        x509Certificate.setValue(certificateDto.getCertificate());

        X509Data x509Data = new X509DataBuilder().buildObject();
        x509Data.getX509Certificates().add(x509Certificate);

        KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
        keyInfo.getKeyNames().add(keyName);
        keyInfo.getX509Datas().add(x509Data);

        KeyDescriptor keyDescriptor = new KeyDescriptorBuilder().buildObject();
        keyDescriptor.setUse(UsageType.valueOf(certificateDto.getKeyUse().toString()));
        keyDescriptor.setKeyInfo(keyInfo);

        return keyDescriptor;
    }
}
