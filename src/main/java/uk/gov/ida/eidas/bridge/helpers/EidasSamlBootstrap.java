package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import uk.gov.ida.eidas.saml.extensions.RequestedAttribute;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributeBuilder;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributeImpl;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributes;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributesBuilder;
import uk.gov.ida.eidas.saml.extensions.RequestedAttributesImpl;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeBuilder;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;
import uk.gov.ida.saml.core.IdaSamlBootstrap;

public class EidasSamlBootstrap {

    private EidasSamlBootstrap () { }

    public static void bootstrap() {
        IdaSamlBootstrap.bootstrap();
        XMLObjectProviderRegistrySupport.registerObjectProvider(SPType.DEFAULT_ELEMENT_NAME, new SPTypeBuilder(), SPTypeImpl.MARSHALLER, SPTypeImpl.UNMARSHALLER);
        XMLObjectProviderRegistrySupport.registerObjectProvider(RequestedAttributes.DEFAULT_ELEMENT_NAME, new RequestedAttributesBuilder(), RequestedAttributesImpl.MARSHALLER, RequestedAttributesImpl.UNMARSHALLER);
        XMLObjectProviderRegistrySupport.registerObjectProvider(RequestedAttribute.DEFAULT_ELEMENT_NAME, new RequestedAttributeBuilder(), RequestedAttributeImpl.MARSHALLER, RequestedAttributeImpl.UNMARSHALLER);
    }

}
