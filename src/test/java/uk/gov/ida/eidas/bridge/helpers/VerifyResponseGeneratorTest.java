package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.saml.core.domain.Gender;

import static org.junit.Assert.*;

public class VerifyResponseGeneratorTest {

    private final String BRIDGE_ENTITY_ID = "bridge-entity-id";
    private final String assertionConsumerServiceLocation = "http://some-destination";
    private EidasIdentityAssertion eidasIdentityAssertion;

    @Before
    public void before() {
        eidasIdentityAssertion = new EidasIdentityAssertion("Ab", "ba", "holborn", Gender.FEMALE, new DateTime(1965, 1, 1, 0, 0));
    }


    @Test
    public void shouldGenerateAResponse() {
        VerifyResponseGenerator verifyResponseGenerator = new VerifyResponseGenerator(BRIDGE_ENTITY_ID, new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID), new AuthnStatementAssertionGenerator());
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, "responseTo", eidasIdentityAssertion);
        assertNotNull(response);

        assertEquals(assertionConsumerServiceLocation, response.getDestination());
        assertNotNull(response.getID());
        assertNotNull(response.getInResponseTo());
        assertNotNull(response.getIssueInstant());
    }

    @Test
    public void shouldGenerateAResponseWithIssue() {
        VerifyResponseGenerator verifyResponseGenerator = new VerifyResponseGenerator(BRIDGE_ENTITY_ID, new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID), new AuthnStatementAssertionGenerator());
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, "responseTo", eidasIdentityAssertion);
        assertNotNull(response);

        Issuer issuer = response.getIssuer();
        assertNotNull(issuer);
        assertEquals(NameIDType.ENTITY, issuer.getFormat());
        assertEquals(BRIDGE_ENTITY_ID, issuer.getValue());
    }

    @Test
    public void shouldGenerateAResponseWithStatus() {
        VerifyResponseGenerator verifyResponseGenerator = new VerifyResponseGenerator(BRIDGE_ENTITY_ID, new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID), new AuthnStatementAssertionGenerator());
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, "responseTo", eidasIdentityAssertion);
        assertNotNull(response);

        Status status = response.getStatus();
        assertNotNull(status);
        StatusCode statusCode = status.getStatusCode();
        assertNotNull(statusCode);
        assertEquals(StatusCode.SUCCESS, statusCode.getValue());
    }

    @Test
    public void shouldGenerateAResponseWithAssertions() {
        VerifyResponseGenerator verifyResponseGenerator = new VerifyResponseGenerator(BRIDGE_ENTITY_ID, new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID), new AuthnStatementAssertionGenerator());
        Response response = verifyResponseGenerator.generateResponse(assertionConsumerServiceLocation, "responseTo", eidasIdentityAssertion);
        assertNotNull(response);

        assertTrue("There should be two assertions (Matching Dataset and AuthnStatement)", response.getAssertions().size() == 2);
    }
}
