package uk.gov.ida.eidas.saml.extensions;

import org.opensaml.saml.common.SAMLObject;

import javax.xml.namespace.QName;

public interface RequestedAttributes extends SAMLObject {
    String DEFAULT_ELEMENT_LOCAL_NAME = "RequestedAttributes";

    QName DEFAULT_ELEMENT_NAME = new QName(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, DEFAULT_ELEMENT_LOCAL_NAME, NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
}
