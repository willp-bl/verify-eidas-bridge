package uk.gov.ida.eidas.saml.extensions;

import uk.gov.ida.saml.core.extensions.StringValueSamlObject;

import javax.xml.namespace.QName;

public interface SPType extends StringValueSamlObject {

    String DEFAULT_ELEMENT_LOCAL_NAME = "SPType";

    QName DEFAULT_ELEMENT_NAME = new QName(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, DEFAULT_ELEMENT_LOCAL_NAME, NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
}
