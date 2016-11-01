package uk.gov.ida.eidas.bridge;

import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import uk.gov.ida.eidas.bridge.resources.EidasBridgeResource;

public class BridgeApplication extends Application<BridgeConfiguration> {
    public static void main(String[] args) throws Exception {
        if (args == null || args.length == 0) {
            args = new String[] { "server", System.getenv("YML_CONFIG_PATH") };
        }
        new BridgeApplication().run(args);
    }


    @Override
    public void initialize(Bootstrap<BridgeConfiguration> bootstrap) {
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false)
                )
        );
    }

    @Override
    public void run(BridgeConfiguration configuration,
                    Environment environment) throws ClassNotFoundException {

        environment.jersey().register(new EidasBridgeResource());

    }
}
