package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import org.joda.time.DateTime;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import uk.gov.ida.duplicates.SamlResponseAssertionEncrypter;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.helpers.RandomIdGenerator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;

public class VerifyResponseGenerator {

    private final String bridgeEntityId;
    private final MatchingDatasetAssertionGenerator matchingDatasetAssertionGenerator;
    private final AuthnStatementAssertionGenerator authnStatementAssertionGenerator;
    private final SamlResponseAssertionEncrypter samlResponseAssertionEncrypter;
    private final SigningHelper signingHelper;


    public VerifyResponseGenerator(
        String bridgeEntityId,
        MatchingDatasetAssertionGenerator matchingDatasetAssertionGenerator,
        AuthnStatementAssertionGenerator authnStatementAssertionGenerator,
        SamlResponseAssertionEncrypter samlResponseAssertionEncrypter, SigningHelper signingHelper) {
        this.bridgeEntityId = bridgeEntityId;
        this.matchingDatasetAssertionGenerator = matchingDatasetAssertionGenerator;
        this.authnStatementAssertionGenerator = authnStatementAssertionGenerator;
        this.samlResponseAssertionEncrypter = samlResponseAssertionEncrypter;
        this.signingHelper = signingHelper;
    }

    public Response generateResponse(String assertionConsumerServiceLocation, String inResponseTo, String ipAddress, EidasIdentityAssertion eidasIdentityAssertion) throws MarshallingException, SecurityException, SignatureException {
        Response response = new ResponseBuilder().buildObject();
        response.setDestination(assertionConsumerServiceLocation);
        response.setID(RandomIdGenerator.generateRandomId());
        response.setInResponseTo(inResponseTo);
        response.setIssueInstant(new DateTime());

        setIssuer(response);
        setStatus(response);
        setAssertions(response, inResponseTo, ipAddress, eidasIdentityAssertion);
        samlResponseAssertionEncrypter.encryptAssertions(response);

        return signingHelper.sign(response);
    }

    private void setIssuer(Response response) {
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setFormat(NameIDType.ENTITY);
        issuer.setValue(bridgeEntityId);
        response.setIssuer(issuer);
    }

    private void setStatus(Response response) {
        Status status = new StatusBuilder().buildObject();
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);
    }

    private void setAssertions(Response response, String inResponseTo, String ipAddress, EidasIdentityAssertion eidasIdentityAssertion) throws MarshallingException, SecurityException, SignatureException {
        response.getAssertions().add(matchingDatasetAssertionGenerator.generate(inResponseTo, eidasIdentityAssertion));
        response.getAssertions().add(authnStatementAssertionGenerator.generate(inResponseTo, ipAddress, eidasIdentityAssertion.getPersonIdentifier()));
    }
}
