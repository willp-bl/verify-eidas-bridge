package uk.gov.ida.eidas.bridge.domain;

import org.joda.time.DateTime;
import uk.gov.ida.saml.core.domain.Gender;

import java.util.Optional;

public class EidasIdentityAssertion {
    private final String firstName;
    private final String familyName;
    private final Optional<String> currentAddress;
    private final Optional<Gender> gender;
    private final DateTime dateOfBirth;
    private final String personIdentifier;

    public EidasIdentityAssertion(String firstName, String familyName, Optional<String> currentAddress, Optional<Gender> gender, DateTime dateOfBirth, String personIdentifier) {
        this.firstName = firstName;
        this.familyName = familyName;
        this.currentAddress = currentAddress;
        this.gender = gender;
        this.dateOfBirth = dateOfBirth;
        this.personIdentifier = personIdentifier;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public Optional<String> getCurrentAddress() {
        return currentAddress;
    }

    public Optional<Gender> getGender() {
        return gender;
    }

    public DateTime getDateOfBirth() {
        return dateOfBirth;
    }

    public String getPersonIdentifier() {
        return personIdentifier;
    }
}
