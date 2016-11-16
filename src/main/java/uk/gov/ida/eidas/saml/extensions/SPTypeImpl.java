package uk.gov.ida.eidas.saml.extensions;

import uk.gov.ida.saml.core.extensions.impl.StringValueSamlObjectImpl;

public class SPTypeImpl extends StringValueSamlObjectImpl implements SPType {
    protected SPTypeImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }
}
