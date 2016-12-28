package uk.gov.ida.duplicates;

import com.google.common.base.Throwables;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import uk.gov.ida.saml.security.EncrypterFactory;
import uk.gov.ida.saml.security.EncryptionCredentialFactory;
import uk.gov.ida.saml.security.EntityToEncryptForLocator;

import java.util.List;

/**
 * Adapted from {@link uk.gov.ida.saml.core.transformers.outbound.decorators.SamlResponseAssertionEncrypter} which lives in verify/saml-utils.
 */
public class SamlResponseAssertionEncrypter {
    private final EncryptionCredentialFactory credentialFactory;
    private final EncrypterFactory encrypterFactory;
    private final EntityToEncryptForLocator entityToEncryptForLocator;

    public SamlResponseAssertionEncrypter(
        final EncryptionCredentialFactory credentialFactory,
        final EncrypterFactory encrypterFactory,
        final EntityToEncryptForLocator entityToEncryptForLocator) {

        this.encrypterFactory = encrypterFactory;
        this.entityToEncryptForLocator = entityToEncryptForLocator;
        this.credentialFactory = credentialFactory;
    }

    public Response encryptAssertions(final Response samlMessage) {
        if (getAssertions(samlMessage).size() > 0) {
            String entityToEncryptFor = entityToEncryptForLocator.fromRequestId(getRequestId(samlMessage));
            Credential credential = credentialFactory.getEncryptingCredential(entityToEncryptFor);

            Encrypter samlEncrypter = encrypterFactory.createEncrypter(credential);

            for (Assertion assertion : getAssertions(samlMessage)) {
                try {
                    EncryptedAssertion encryptedAssertion = samlEncrypter.encrypt(assertion);
                    getEncryptedAssertions(samlMessage).add(encryptedAssertion);
                } catch (EncryptionException e) {
                    throw Throwables.propagate(e);
                }
            }
            getAssertions(samlMessage).removeAll(getAssertions(samlMessage));
        }
        return samlMessage;
    }

    private String getRequestId(final Response response) {
        return response.getInResponseTo();
    }

    private List<EncryptedAssertion> getEncryptedAssertions(final Response response) {
        return response.getEncryptedAssertions();
    }

    private List<Assertion> getAssertions(final Response response) {
        return response.getAssertions();
    }
}
