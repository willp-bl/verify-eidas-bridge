package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

public class SigningHelper {
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private final Credential signingCredential;
    private final X509Credential x509SigningCredential;
    private final KeyInfoGenerator keyInfoGenerator;

    public SigningHelper(Credential signingCredential, X509Credential x509SigningCredential, KeyInfoGenerator keyInfoGenerator) {
        this.signingCredential = signingCredential;
        this.x509SigningCredential = x509SigningCredential;
        this.keyInfoGenerator = keyInfoGenerator;
    }

    public <T extends SignableSAMLObject> T sign(T signableSAMLObject) throws MarshallingException, SignatureException, SecurityException {
        Signature signature = openSamlXmlObjectFactory.createSignature();
        signature.setKeyInfo(keyInfoGenerator.generate(x509SigningCredential));
        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signableSAMLObject.setSignature(signature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(signableSAMLObject).marshall(signableSAMLObject);
        Signer.signObject(signature);

        return signableSAMLObject;
    }
}
