package uk.gov.ida.eidas.bridge.factories;

import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.BasicRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.eidas.bridge.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.hub.transformers.inbound.decorators.AuthnRequestSizeValidator;
import uk.gov.ida.saml.hub.validators.StringSizeValidator;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.KeyStoreLoader;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;
import uk.gov.ida.saml.metadata.modules.MetadataModule;
import uk.gov.ida.saml.security.MetadataBackedSignatureValidator;

import javax.annotation.Nullable;
import java.security.KeyStore;

public class VerifyEidasBridgeFactory {

    private final Environment environment;
    private final MetadataConfiguration verifyMetadataConfiguration;
    private final MetadataConfiguration eidasMetadataConfiguration;
    private final CoreTransformersFactory coreTransformersFactory = new CoreTransformersFactory();
    private final MetadataModule metadataModule = new MetadataModule();

    @Nullable
    private MetadataResolver verifyMetadataResolver;
    @Nullable
    private MetadataResolver eidasMetadataResolver;
    @Nullable
    private MetadataBackedSignatureValidator metadataBackedSignatureValidator;
    @Nullable
    private AuthnRequestHandler authnRequestHandler;

    public VerifyEidasBridgeFactory(
        Environment environment,
        BridgeConfiguration configuration) {
        this.environment = environment;
        this.verifyMetadataConfiguration = configuration.getVerifyMetadataConfiguration();
        this.eidasMetadataConfiguration = configuration.getEidasMetadataConfiguration();
    }

    public AuthnRequestHandler getAuthnRequestHandler() throws ComponentInitializationException {
        if (authnRequestHandler == null) {
            StringSizeValidator stringSizeValidator = new StringSizeValidator();
            AuthnRequestSizeValidator authnRequestSizeValidator = new AuthnRequestSizeValidator(stringSizeValidator);
            StringToOpenSamlObjectTransformer<AuthnRequest> stringToAuthnRequest =
                coreTransformersFactory.getStringtoOpenSamlObjectTransformer(authnRequestSizeValidator);
            authnRequestHandler = new AuthnRequestHandler(
                this.verifyMetadataConfiguration,
                getVerifyMetadataBackedSignatureValidator(),
                stringToAuthnRequest);
        }
        return authnRequestHandler;
    }

    public MetadataResolver getVerifyMetadataResolver() {
        if (verifyMetadataResolver == null) {
            verifyMetadataResolver = getMetadataResolver(verifyMetadataConfiguration);
        }
        return verifyMetadataResolver;
    }

    public MetadataResolver getEidasMetadataResolver() {
        if (eidasMetadataResolver == null) {
            eidasMetadataResolver = getMetadataResolver(eidasMetadataConfiguration);
        }
        return eidasMetadataResolver;
    }

    private MetadataResolver getMetadataResolver(MetadataConfiguration metadataConfiguration) {
        KeyStore keyStore = new KeyStoreLoader().load(
            metadataConfiguration.getTrustStorePath(),
            metadataConfiguration.getTrustStorePassword()
        );
        return metadataModule.metadataResolver(
            metadataConfiguration.getUri(),
            metadataConfiguration.getMaxRefreshDelay(),
            metadataConfiguration.getMinRefreshDelay(),
            environment,
            metadataConfiguration,
            new ExpiredCertificateMetadataFilter(),
            new PKIXSignatureValidationFilterProvider(keyStore)
        );
    }

    private MetadataBackedSignatureValidator getVerifyMetadataBackedSignatureValidator() throws ComponentInitializationException {
        if (metadataBackedSignatureValidator == null) {
            BasicRoleDescriptorResolver basicRoleDescriptorResolver = new BasicRoleDescriptorResolver(getVerifyMetadataResolver());
            basicRoleDescriptorResolver.initialize();
            MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
            metadataCredentialResolver.setRoleDescriptorResolver(basicRoleDescriptorResolver);
            metadataCredentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
            metadataCredentialResolver.initialize();
            ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine = new ExplicitKeySignatureTrustEngine(
                metadataCredentialResolver, DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
            );
            metadataBackedSignatureValidator = MetadataBackedSignatureValidator.withoutCertificateChainValidation(explicitKeySignatureTrustEngine);
        }
        return metadataBackedSignatureValidator;
    }
}
