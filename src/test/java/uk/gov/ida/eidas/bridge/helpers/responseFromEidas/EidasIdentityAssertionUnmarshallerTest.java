package uk.gov.ida.eidas.bridge.helpers.responseFromEidas;

import io.dropwizard.testing.ResourceHelpers;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;
import uk.gov.ida.saml.core.domain.Gender;
import uk.gov.ida.saml.deserializers.parser.SamlObjectParser;
import uk.gov.ida.saml.security.validators.ValidatedAssertions;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static java.util.Collections.singletonList;
import static org.junit.Assert.assertEquals;

public class EidasIdentityAssertionUnmarshallerTest {

    private EidasIdentityAssertionUnmarshaller eidasIdentityAssertionUnmarshaller;

    @Before
    public void before(){
        EidasSamlBootstrap.bootstrap();
        eidasIdentityAssertionUnmarshaller = new EidasIdentityAssertionUnmarshaller();
    }

    @Test
    public void canUnpackAValidatedAssertionIntoAnEidasIdentityAssertion() throws Exception {
        Assertion samlObject = buildAssertionFromFile();

        ValidatedAssertions validatedAssertions = new ValidatedAssertions(singletonList(samlObject));
        EidasIdentityAssertion result = eidasIdentityAssertionUnmarshaller.unmarshallAssertion(validatedAssertions);

        assertEquals("javier", result.getFirstName());
        assertEquals("Current Address", result.getCurrentAddress().get());
        assertEquals(Gender.MALE, result.getGender().get());
        assertEquals(new DateTime(1965, 1, 1, 0, 0), result.getDateOfBirth());
        assertEquals("CA/UK/12345", result.getPersonIdentifier());
    }

    @Test
    public void shouldIgnoreNonLatinAttributeValues() throws Exception {
        Assertion samlObject = buildAssertionFromFile();

        ValidatedAssertions validatedAssertions = new ValidatedAssertions(singletonList(samlObject));
        EidasIdentityAssertion result = eidasIdentityAssertionUnmarshaller.unmarshallAssertion(validatedAssertions);

        assertEquals("Onases", result.getFamilyName());
    }

    private Assertion buildAssertionFromFile() throws IOException, javax.xml.parsers.ParserConfigurationException, org.xml.sax.SAXException, org.opensaml.core.xml.io.UnmarshallingException {
        String xmlString = new String(Files.readAllBytes(Paths.get(ResourceHelpers.resourceFilePath("EIDASIdentityAssertion.xml"))));
        return (Assertion) new SamlObjectParser().getSamlObject(xmlString);
    }

}
