package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;

public class VerifyResponseGenerator {

    private final String bridgeEntityId;
    private final MatchingDatasetAssertionGenerator matchingDatasetAssertionGenerator;
    private final AuthnStatementAssertionGenerator authnStatementAssertionGenerator;

    public VerifyResponseGenerator(
        String bridgeEntityId,
        MatchingDatasetAssertionGenerator matchingDatasetAssertionGenerator,
        AuthnStatementAssertionGenerator authnStatementAssertionGenerator) {
        this.bridgeEntityId = bridgeEntityId;
        this.matchingDatasetAssertionGenerator = matchingDatasetAssertionGenerator;
        this.authnStatementAssertionGenerator = authnStatementAssertionGenerator;
    }

    public Response generateResponse(String assertionConsumerServiceLocation, String inResponseTo, EidasIdentityAssertion eidasIdentityAssertion) {
        Response response = new ResponseBuilder().buildObject();
        response.setDestination(assertionConsumerServiceLocation);
        response.setID(RandomIdGenerator.generateRandomId());
        response.setInResponseTo(inResponseTo);
        response.setIssueInstant(new DateTime());

        setIssuer(response);
        setStatus(response);
        setAssertions(response, inResponseTo, eidasIdentityAssertion);

        return response;
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

    private void setAssertions(Response response, String inResponseTo, EidasIdentityAssertion eidasIdentityAssertion) {
        response.getAssertions().add(matchingDatasetAssertionGenerator.generate(inResponseTo, eidasIdentityAssertion));
        response.getAssertions().add(authnStatementAssertionGenerator.generate());
    }
}
