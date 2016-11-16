package uk.gov.ida.eidas.saml.extensions;

import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

public class RequestedAttributeBuilder extends AbstractSAMLObjectBuilder<RequestedAttribute> {

    public RequestedAttribute buildObject() {
        return buildObject(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, RequestedAttribute.DEFAULT_ELEMENT_LOCAL_NAME,
            NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
    }

    public RequestedAttribute buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new RequestedAttributeImpl(namespaceURI, localName, namespacePrefix);
    }
}

