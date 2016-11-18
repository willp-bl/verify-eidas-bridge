package uk.gov.ida.eidas.bridge;

import com.codahale.metrics.health.HealthCheck;
import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.factories.VerifyEidasBridgeFactory;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;
import uk.gov.ida.eidas.bridge.helpers.EidasAuthnRequestGenerator;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;
import uk.gov.ida.eidas.bridge.resources.VerifyAuthnRequestResource;
import uk.gov.ida.saml.dropwizard.metadata.MetadataHealthCheck;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Map;

import static com.google.common.collect.ImmutableMap.of;


public class BridgeApplication extends Application<BridgeConfiguration> {
    public static void main(String[] args) throws Exception {
        if (args == null || args.length == 0) {
            args = new String[] { "server", System.getenv("YML_CONFIG_PATH") };
        }
        new BridgeApplication().run(args);
    }

    @Override
    public void initialize(Bootstrap<BridgeConfiguration> bootstrap) {
        EidasSamlBootstrap.bootstrap();

        bootstrap.addBundle(new ViewBundle<>());
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(true)
                )
        );
    }

    @Override
    public void run(BridgeConfiguration configuration, Environment environment) throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        VerifyEidasBridgeFactory verifyEidasBridgeFactory = new VerifyEidasBridgeFactory(environment, configuration);

        AuthnRequestHandler authnRequestHandler = verifyEidasBridgeFactory.getAuthnRequestHandler();
        EidasAuthnRequestGenerator eidasAuthnRequestGenerator = verifyEidasBridgeFactory.getEidasAuthnRequestGenerator();
        environment.jersey().register(new VerifyAuthnRequestResource(authnRequestHandler, eidasAuthnRequestGenerator));

        Map<String, HealthCheck> healthChecks = of(
            "verify-metadata", new MetadataHealthCheck(verifyEidasBridgeFactory.getVerifyMetadataResolver(), configuration.getVerifyMetadataConfiguration().getExpectedEntityId()),
            "eidas-metadata", new MetadataHealthCheck(verifyEidasBridgeFactory.getEidasMetadataResolver(), configuration.getEidasMetadataConfiguration().getExpectedEntityId())
        );
        healthChecks.entrySet().stream().forEach(x -> environment.healthChecks().register(x.getKey(), x.getValue()));
    }

}
