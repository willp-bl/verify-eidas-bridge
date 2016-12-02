package uk.gov.ida.eidas.bridge.helpers;

import java.util.UUID;

public class RandomIdGenerator {
    public static String generateRandomId(){
        // The ID needs to conform to the NCName specification. From https://www.w3.org/TR/1999/REC-xml-names-19990114/#NT-NCName
        //
        //       NCName    ::=    (Letter | '_') (NCNameChar)*
        //   NCNameChar    ::=    Letter | Digit | '.' | '-' | '_' | CombiningChar | Extender

        return "_" + UUID.randomUUID().toString();
    }
}
