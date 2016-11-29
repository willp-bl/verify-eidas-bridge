package uk.gov.ida.eidas.bridge.testhelpers;

import com.google.common.base.Throwables;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.security.CredentialFactorySignatureValidator;
import uk.gov.ida.saml.security.SigningCredentialFactory;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.List;

import static java.util.Collections.singletonList;

public class TestSignatureValidator {

    public static CredentialFactorySignatureValidator getSignatureValidator() {
        return new CredentialFactorySignatureValidator(new SigningCredentialFactory(TestSignatureValidator::getPublicKeys));
    }

    private static List<PublicKey> getPublicKeys(String entityId) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream certificateStream = new ByteArrayInputStream(Base64.decode(TestCertificateStrings.TEST_PUBLIC_CERT));
            PublicKey publicKey = certificateFactory.generateCertificate(certificateStream).getPublicKey();
            return singletonList(publicKey);
        } catch (CertificateException | Base64DecodingException e) {
            throw Throwables.propagate(e);
        }
    }
}
