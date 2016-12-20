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
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.transformers.KeyDescriptorsUnmarshaller;

import java.util.ArrayList;
import java.util.List;

public class BridgeMetadataGenerator {


    private final String hostname;
    private final String entityId;
    private final KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller;
    private final Certificate signingCertificate;
    private final Certificate encryptingCertificate;
    private final SigningHelper signingHelper;
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();


    public BridgeMetadataGenerator(
        String hostname, String entityId,
        KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller,
        Certificate signingCertificate,
        Certificate encryptingCertificate,
        SigningHelper signingHelper) {
        this.hostname = hostname;
        this.entityId = entityId;
        this.keyDescriptorsUnmarshaller = keyDescriptorsUnmarshaller;
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
        entityDescriptor.getRoleDescriptors().add(getSpSsoDescriptor(openSamlXmlObjectFactory));
        entityDescriptor.setID("bridgeEntityDescriptor");

        signingHelper.sign(entityDescriptor);
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
        signingHelper.sign(spSsoDescriptor);
        return spSsoDescriptor;
    }
}
