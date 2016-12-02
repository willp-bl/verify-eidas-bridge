package uk.gov.ida.eidas.bridge.testhelpers;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.saml.core.test.builders.ResponseBuilder;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

public class ResponseStringBuilder extends ResponseBuilder {

    private static final XmlObjectToBase64EncodedStringTransformer toBase64EncodedString = new XmlObjectToBase64EncodedStringTransformer();

    public static String buildString(ResponseBuilder responseBuilder) throws MarshallingException, SignatureException {
        return toBase64EncodedString.apply(responseBuilder.build());
    }
}
