package uk.gov.ida.eidas.saml.extensions;

import org.opensaml.saml.saml2.core.Attribute;

import javax.xml.namespace.QName;

public interface RequestedAttribute extends Attribute {

    String DEFAULT_ELEMENT_LOCAL_NAME = "RequestedAttribute";
    String IS_REQUIRED_ATTRIB_NAME = "isRequired";

    QName DEFAULT_ELEMENT_NAME = new QName(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, DEFAULT_ELEMENT_LOCAL_NAME,
        NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);

    Boolean isRequired();

    void setIsRequired(Boolean isRequired);
}
