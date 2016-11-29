package uk.gov.ida.eidas.saml.extensions;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.opensaml.saml.common.AbstractSAMLObjectBuilder;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class SPTypeBuilder extends AbstractSAMLObjectBuilder<SPType> {

    @Nonnull
    @Override
    public SPType buildObject() {
        return buildObject(NamespaceConstants.EIDAS_EXTENSIONS_NAMESPACE, SPType.DEFAULT_ELEMENT_LOCAL_NAME, NamespaceConstants.EIDAS_EXTENSIONS_LOCAL_NAME);
    }

    @Nonnull
    @Override
    public SPType buildObject(@Nullable String namespaceURI, @Nonnull @NotEmpty String localName, @Nullable String namespacePrefix) {
        return new SPTypeImpl(namespaceURI, localName, namespacePrefix);

    }
}
