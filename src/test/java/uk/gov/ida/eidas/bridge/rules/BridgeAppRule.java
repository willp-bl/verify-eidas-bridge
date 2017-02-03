package uk.gov.ida.eidas.bridge.rules;

import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.junit.DropwizardAppRule;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.configuration.CountryConfiguration;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static java.util.Arrays.asList;

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

    // Need a supplier that will return a string url - we need wiremock to initialise before we try and read the url
    public static BridgeAppRule createBridgeAppRuleFromConfig(Supplier<String> verifyMetadataUri, Map<String, Supplier<CountryConfiguration>> countryConfig) {
        EidasSamlBootstrap.bootstrap();
        List<Map.Entry<String, Supplier<CountryConfiguration>>> entries = countryConfig.entrySet().stream().collect(Collectors.toList());
        ConfigOverride.config("eidasMetadata.countries", "[{},{}]");
        Stream<ConfigOverride> countryConfigOverrides = IntStream.range(0, entries.size()).mapToObj(idx -> {
            String key = entries.get(idx).getKey();
            Supplier<CountryConfiguration> value = entries.get(idx).getValue();
            return asList(
                ConfigOverride.config(String.format("eidasMetadata.countries[%s].base64Value", idx), metadataTrustStore),
                ConfigOverride.config(String.format("eidasMetadata.countries[%s].password", idx), KEYSTORE_PASSWORD),
                ConfigOverride.config(String.format("eidasMetadata.countries[%s].entityID", idx), () -> value.get().getEntityID()),
                ConfigOverride.config(String.format("eidasMetadata.countries[%s].workaroundBrokenRoleDescriptorSignatures", idx), () -> Boolean.toString(value.get().workaroundBrokenRoleDescriptorSignatures())),
                ConfigOverride.config(String.format("eidasMetadata.countries[%s].countryCode", idx), key)
            );
        }).flatMap(Collection::stream);

        List<ConfigOverride> configOverrides = asList(
            ConfigOverride.config("verifyMetadata.trustStorePath", "test_metadata_truststore.ts"),
            ConfigOverride.config("verifyMetadata.uri", verifyMetadataUri),
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
            ConfigOverride.config("sessionCookie.secretSeed", SECRET_SEED)
        );
        return new BridgeAppRule(Stream.concat(configOverrides.stream(), countryConfigOverrides).toArray(ConfigOverride[]::new));
    }

    public static BridgeAppRule createBridgeAppRule(Supplier<String> verifyMetadataUri, Map<String, Supplier<String>> countryConfig) {
        Map<String, Supplier<CountryConfiguration>> configMap = countryConfig.entrySet().stream()
            .collect(
                Collectors.toMap(
                    Map.Entry::getKey,
                    entry -> () -> new CountryConfiguration(entry.getValue().get(), entry.getKey(), null, false)
                )
        );
        return createBridgeAppRuleFromConfig(verifyMetadataUri, configMap);
    }

    public String getHostname() {
        return HOSTNAME;
    }

    public String getSecretSeed() {
        return SECRET_SEED;
    }

    private BridgeAppRule(ConfigOverride... configOverrides) {
        super(BridgeApplication.class, "eidasbridge-test.yml", configOverrides);
    }
}
