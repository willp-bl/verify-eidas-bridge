package uk.gov.ida.eidas.bridge.testhelpers;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class SigningHelperBuilder {

    public static SigningHelperBuilder aSigningHelper() {
        return new SigningHelperBuilder();
    }

    public SigningHelper build() {
        Credential signingCredential = new TestCredentialFactory(TestCertificateStrings.TEST_PUBLIC_CERT, TestCertificateStrings.TEST_PRIVATE_KEY).getSigningCredential();
        Certificate signingCertificate =  new X509CertificateFactory().createCertificate(TestCertificateStrings.TEST_PUBLIC_CERT);
        BasicX509Credential x509SigningCredential = new BasicX509Credential((X509Certificate) signingCertificate);
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        return new SigningHelper(signingCredential, x509SigningCredential, keyInfoGenerator);
    }
}
