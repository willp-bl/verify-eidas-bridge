package uk.gov.ida.eidas.bridge.domain;

import org.joda.time.DateTime;
import uk.gov.ida.saml.core.domain.Gender;

public class EidasIdentityAssertion {
    private final String firstName;
    private final String familyName;
    private final String currentAddress;
    private final Gender gender;
    private final DateTime dateOfBirth;

    public EidasIdentityAssertion(String firstName, String familyName, String currentAddress, Gender gender, DateTime dateOfBirth) {
        this.firstName = firstName;
        this.familyName = familyName;
        this.currentAddress = currentAddress;
        this.gender = gender;
        this.dateOfBirth = dateOfBirth;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getCurrentAddress() {
        return currentAddress;
    }

    public Gender getGender() {
        return gender;
    }

    public DateTime getDateOfBirth() {
        return dateOfBirth;
    }
}
