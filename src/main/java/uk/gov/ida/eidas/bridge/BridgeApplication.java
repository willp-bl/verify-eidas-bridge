package uk.gov.ida.eidas.bridge;

import com.codahale.metrics.health.HealthCheck;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.ResourceConfigurationSourceProvider;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.dhatim.dropwizard.jwt.cookie.authentication.JwtCookieAuthBundle;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.exceptions.MarshallingExceptionMapper;
import uk.gov.ida.eidas.bridge.exceptions.SamlTransformationErrorMapper;
import uk.gov.ida.eidas.bridge.exceptions.SecurityExceptionMapper;
import uk.gov.ida.eidas.bridge.exceptions.SignatureExceptionMapper;
import uk.gov.ida.eidas.bridge.factories.VerifyEidasBridgeFactory;
import uk.gov.ida.eidas.bridge.helpers.EidasSamlBootstrap;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Map;

import static com.google.common.collect.ImmutableMap.of;


public class BridgeApplication extends Application<BridgeConfiguration> {

    static {
        System.setProperty("org.jboss.logging.provider", "slf4j");
    }

    public static void main(String[] args) throws Exception {
        new BridgeApplication().run("server", "eidasbridge.yml");
    }

    @Override
    public void initialize(Bootstrap<BridgeConfiguration> bootstrap) {
        EidasSamlBootstrap.bootstrap();

        bootstrap.addBundle(new ViewBundle<>());
        bootstrap.addBundle(new AssetsBundle("/assets"));
        bootstrap.addBundle(JwtCookieAuthBundle.<BridgeConfiguration>getDefault().withConfigurationSupplier(BridgeConfiguration::getSessionCookie));
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(new ResourceConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(true)
                )
        );
    }

    @Override
    public void run(BridgeConfiguration configuration, Environment environment) throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, CertificateEncodingException {
        VerifyEidasBridgeFactory verifyEidasBridgeFactory = new VerifyEidasBridgeFactory(environment, configuration);

        environment.jersey().register(verifyEidasBridgeFactory.getVerifyAuthnRequestResource());
        environment.jersey().register(verifyEidasBridgeFactory.getBridgeMetadataResource());
        environment.jersey().register(verifyEidasBridgeFactory.getEidasResponseResource());

        environment.jersey().register(new SamlTransformationErrorMapper());
        environment.jersey().register(new SecurityExceptionMapper());
        environment.jersey().register(new SignatureExceptionMapper());
        environment.jersey().register(new MarshallingExceptionMapper());

        Map<String, HealthCheck> healthChecks = of(
            "verify-metadata", verifyEidasBridgeFactory.getVerifyMetadataHealthcheck(),
            "eidas-metadata", verifyEidasBridgeFactory.getEidasMetadataHealthcheck()
        );
        healthChecks.entrySet().forEach(x -> environment.healthChecks().register(x.getKey(), x.getValue()));
    }

}
