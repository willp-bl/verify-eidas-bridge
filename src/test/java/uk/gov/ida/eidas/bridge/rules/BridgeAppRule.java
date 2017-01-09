package uk.gov.ida.eidas.bridge.rules;

import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.junit.DropwizardAppRule;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.util.function.Supplier;

public class BridgeAppRule extends DropwizardAppRule<BridgeConfiguration> {

    private static final String KEYSTORE_PASSWORD = "fooBar";
    private static final String EIDAS_SIGNING_KEY_ALIAS = "leaf-stub-sp-metadata-signing";
    private static final String VERIFY_SIGNING_KEY_ALIAS = "1";
    private static final String ENCRYPTING_KEY_ALIAS = "leaf-stub-sp-encryption";
    private static final String eidasSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedKeyStore(EIDAS_SIGNING_KEY_ALIAS, KEYSTORE_PASSWORD);

    private static final String verifySigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedKeyStore(VERIFY_SIGNING_KEY_ALIAS, KEYSTORE_PASSWORD);
    private static final String encodedEncryptingKeyStore = TestSigningKeyStoreProvider.getBase64EncodedKeyStore(ENCRYPTING_KEY_ALIAS, KEYSTORE_PASSWORD);
    private static final String metadataTrustStore = TestSigningKeyStoreProvider.getBase64EncodedTrustStore(TestCertificateStrings.METADATA_SIGNING_A_PUBLIC_CERT, KEYSTORE_PASSWORD) ;
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String HOSTNAME = "hostname";
    private static final String SECRET_SEED = "SECRET_SEED";

    public String getHostname() {
        return HOSTNAME;
    }

    public String getSecretSeed() {
        return SECRET_SEED;
    }

    public BridgeAppRule(Supplier<String> verifyMetadataUri, Supplier<String> eidasMetadataUri) {
        super(BridgeApplication.class,
                "eidasbridge-test.yml",
                ConfigOverride.config("verifyMetadata.trustStorePath", "test_metadata_truststore.ts"),
                ConfigOverride.config("verifyMetadata.uri", verifyMetadataUri),
                ConfigOverride.config("eidasMetadata.countries[0].base64Value", metadataTrustStore),
                ConfigOverride.config("eidasMetadata.countries[0].password", KEYSTORE_PASSWORD),
                ConfigOverride.config("eidasMetadata.countries[0].entityID", eidasMetadataUri),
                ConfigOverride.config("destinationNodeEntityId", eidasMetadataUri),
                ConfigOverride.config("eidasSigningKeyStore.base64Value", eidasSigningKeyStore),
                ConfigOverride.config("eidasSigningKeyStore.password", KEYSTORE_PASSWORD),
                ConfigOverride.config("eidasSigningKeyStore.type", KEYSTORE_TYPE),
                ConfigOverride.config("eidasSigningKeyStore.alias", EIDAS_SIGNING_KEY_ALIAS),
                ConfigOverride.config("verifySigningKeyStore.base64Value", verifySigningKeyStore),
                ConfigOverride.config("verifySigningKeyStore.password", KEYSTORE_PASSWORD),
                ConfigOverride.config("verifySigningKeyStore.type", KEYSTORE_TYPE),
                ConfigOverride.config("verifySigningKeyStore.alias", VERIFY_SIGNING_KEY_ALIAS),
                ConfigOverride.config("encryptingKeyStore.base64Value", encodedEncryptingKeyStore),
                ConfigOverride.config("encryptingKeyStore.password", KEYSTORE_PASSWORD),
                ConfigOverride.config("encryptingKeyStore.type", KEYSTORE_TYPE),
                ConfigOverride.config("encryptingKeyStore.alias", ENCRYPTING_KEY_ALIAS),
                ConfigOverride.config("hostname", HOSTNAME),
                ConfigOverride.config("sessionCookie.secretSeed", SECRET_SEED));
    }
}
