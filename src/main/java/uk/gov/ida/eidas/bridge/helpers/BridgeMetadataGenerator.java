package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.joda.time.Hours;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.transformers.KeyDescriptorsUnmarshaller;

import static java.util.Collections.singletonList;

public class BridgeMetadataGenerator {
    private final String entityId;
    private final KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller;
    private final Certificate signingCertificate;


    public BridgeMetadataGenerator(
        String entityId,
        KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller,
        Certificate signingCertificate) {
        this.entityId = entityId;
        this.keyDescriptorsUnmarshaller = keyDescriptorsUnmarshaller;
        this.signingCertificate = signingCertificate;
    }

    public EntitiesDescriptor generateMetadata() throws SignatureException, MarshallingException {
        EntitiesDescriptor entitiesDescriptor = new EntitiesDescriptorBuilder().buildObject();
        entitiesDescriptor.setID("entitiesDescriptor");
        entitiesDescriptor.setValidUntil(new DateTime().plus(Hours.ONE));

        final EntityDescriptor bridgeEntityDescriptor = createEntityDescriptor(entityId);
        final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
        bridgeEntityDescriptor.getRoleDescriptors().add(getSpSsoDescriptor(openSamlXmlObjectFactory));
        bridgeEntityDescriptor.setID("bridgeEntityDescriptor");
        entitiesDescriptor.getEntityDescriptors().add(bridgeEntityDescriptor);

        return entitiesDescriptor;
    }


    private EntityDescriptor createEntityDescriptor(String entityId) {
        XMLObjectBuilderFactory openSamlBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        EntityDescriptor entityDescriptor = (EntityDescriptor) openSamlBuilderFactory.getBuilder(EntityDescriptor.TYPE_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME, EntityDescriptor.TYPE_NAME);
        entityDescriptor.setEntityID(entityId);
        return entityDescriptor;
    }

    private RoleDescriptor getSpSsoDescriptor(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) throws SignatureException, MarshallingException, SecurityException {
        SPSSODescriptor spSsoDescriptor = openSamlXmlObjectFactory.createSPSSODescriptor();
        spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        spSsoDescriptor.getKeyDescriptors().addAll(keyDescriptorsUnmarshaller.fromCertificates(singletonList(signingCertificate)));
        spSsoDescriptor.setID("spSsoDescriptor");

        return spSsoDescriptor;
    }
}
