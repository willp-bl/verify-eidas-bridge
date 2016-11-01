package uk.gov.ida.eidas.bridge;

import com.yammer.dropwizard.Service;
import com.yammer.dropwizard.assets.AssetsBundle;
import com.yammer.dropwizard.config.Bootstrap;
import com.yammer.dropwizard.config.Environment;
import uk.gov.ida.eidas.bridge.core.Template;
import uk.gov.ida.eidas.bridge.resources.EidasBridgeResource;

public class VerifyEidasBridgeApplication extends Service<VerifyEidasBridgeConfiguration> {
    public static void main(String[] args) throws Exception {
        new VerifyEidasBridgeApplication().run(args);
    }


    @Override
    public void initialize(Bootstrap<VerifyEidasBridgeConfiguration> bootstrap) {
        bootstrap.setName("bridge");
        //bootstrap.addCommand(new RenderCommand());
        bootstrap.addBundle(new AssetsBundle());
    }

    @Override
    public void run(VerifyEidasBridgeConfiguration configuration,
                    Environment environment) throws ClassNotFoundException {

        final Template template = configuration.buildTemplate();

        environment.addResource(new EidasBridgeResource(template));

    }
}
