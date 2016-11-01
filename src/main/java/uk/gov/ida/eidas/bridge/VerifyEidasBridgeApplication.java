package uk.gov.ida.eidas.bridge;

import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import uk.gov.ida.eidas.bridge.core.Template;
import uk.gov.ida.eidas.bridge.resources.EidasBridgeResource;

public class VerifyEidasBridgeApplication extends Application<VerifyEidasBridgeConfiguration> {
    public static void main(String[] args) throws Exception {
        if (args == null || args.length == 0) {
            args = new String[] { "server", com.google.common.io.Resources.getResource("eidasbridge.yml").toString() };
        }
        new VerifyEidasBridgeApplication().run(args);
    }


    @Override
    public void initialize(Bootstrap<VerifyEidasBridgeConfiguration> bootstrap) {
        bootstrap.setName("bridge");
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false)
                )
        );
    }

    @Override
    public void run(VerifyEidasBridgeConfiguration configuration,
                    Environment environment) throws ClassNotFoundException {

        final Template template = configuration.buildTemplate();

        environment.addResource(new EidasBridgeResource(template));

    }
}
