package uk.gov.ida.eidas.bridge.factories;

import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.BasicRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.configuration.SigningKeyStoreConfiguration;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestFormGenerator;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;
import uk.gov.ida.eidas.bridge.helpers.EidasAuthnRequestGenerator;
import uk.gov.ida.eidas.bridge.helpers.SingleSignOnServiceLocator;
import uk.gov.ida.eidas.bridge.resources.BridgeMetadataResource;
import uk.gov.ida.eidas.bridge.resources.VerifyAuthnRequestResource;
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
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import javax.annotation.Nullable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;

public class VerifyEidasBridgeFactory {

    public static final String SIGNING_KEY_ALIAS = "signing";

    private final Environment environment;
    private final MetadataConfiguration verifyMetadataConfiguration;
    private final MetadataConfiguration eidasMetadataConfiguration;
    private final BridgeConfiguration configuration;
    private final CoreTransformersFactory coreTransformersFactory = new CoreTransformersFactory();
    private final MetadataModule metadataModule = new MetadataModule();

    @Nullable
    private MetadataResolver verifyMetadataResolver;
    @Nullable
    private MetadataResolver eidasMetadataResolver;
    @Nullable
    private MetadataBackedSignatureValidator verifyMetadataBackedSignatureValidator;
    @Nullable
    private AuthnRequestHandler authnRequestHandler;
    @Nullable
    private AuthnRequestFormGenerator authnRequestFormGenerator;
    @Nullable
    private EidasAuthnRequestGenerator eidasAuthnRequestGenerator;
    @Nullable
    private SingleSignOnServiceLocator singleSignOnServiceLocator;

    public VerifyEidasBridgeFactory(
        Environment environment,
        BridgeConfiguration configuration) {
        this.environment = environment;
        this.verifyMetadataConfiguration = configuration.getVerifyMetadataConfiguration();
        this.eidasMetadataConfiguration = configuration.getEidasMetadataConfiguration();
        this.configuration = configuration;
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

    public AuthnRequestFormGenerator getAuthnRequestFormGenerator() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        if (authnRequestFormGenerator == null) {
            authnRequestFormGenerator = new AuthnRequestFormGenerator(
                getEidasAuthnRequestGenerator(),
                getSingleSignOnServiceLocator(),
                new XmlObjectToBase64EncodedStringTransformer(),
                configuration.getEidasNodeEntityId());
        }
        return authnRequestFormGenerator;
    }

    public VerifyAuthnRequestResource getVerifyAuthnRequestResource () throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        AuthnRequestHandler authnRequestHandler = this.getAuthnRequestHandler();
        AuthnRequestFormGenerator authnRequestFormGenerator = this.getAuthnRequestFormGenerator();
        return new VerifyAuthnRequestResource(authnRequestHandler, authnRequestFormGenerator);
    }

    public BridgeMetadataResource getBridgeMetadataResource() throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore signingKeyStore = configuration.getSigningKeyStoreConfiguration().getKeyStore();
        java.security.cert.Certificate certificate = signingKeyStore.getCertificate(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS);
        PrivateKey privateKey = (PrivateKey) signingKeyStore.getKey(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS, "fooBar".toCharArray());
        BridgeMetadataFactory bridgeMetadataFactory = new BridgeMetadataFactory(certificate, privateKey, configuration.getBridgeEntityId());
        return bridgeMetadataFactory.getBridgeMetadataResource();
    }

    private MetadataResolver getMetadataResolver(MetadataConfiguration metadataConfiguration) {
        KeyStore keyStore = new KeyStoreLoader().load(
            metadataConfiguration.getTrustStorePath(),
            metadataConfiguration.getTrustStorePassword()
        );
        return  metadataModule.metadataResolver(
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
        if (verifyMetadataBackedSignatureValidator == null) {
            BasicRoleDescriptorResolver basicRoleDescriptorResolver = new BasicRoleDescriptorResolver(getVerifyMetadataResolver());
            basicRoleDescriptorResolver.initialize();
            MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
            metadataCredentialResolver.setRoleDescriptorResolver(basicRoleDescriptorResolver);
            metadataCredentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
            metadataCredentialResolver.initialize();
            ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine = new ExplicitKeySignatureTrustEngine(
                metadataCredentialResolver, DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
            );
            verifyMetadataBackedSignatureValidator = MetadataBackedSignatureValidator.withoutCertificateChainValidation(explicitKeySignatureTrustEngine);
        }
        return verifyMetadataBackedSignatureValidator;
    }

    private EidasAuthnRequestGenerator getEidasAuthnRequestGenerator() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        if (eidasAuthnRequestGenerator == null) {
            SigningKeyStoreConfiguration signingKeyStoreConfiguration = configuration.getSigningKeyStoreConfiguration();
            KeyStore keyStore = signingKeyStoreConfiguration.getKeyStore();
            PublicKey publicKey = keyStore.getCertificate(SIGNING_KEY_ALIAS).getPublicKey();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(SIGNING_KEY_ALIAS, signingKeyStoreConfiguration.getPassword().toCharArray());
            BasicCredential credential = new BasicCredential(publicKey, privateKey);
            eidasAuthnRequestGenerator = new EidasAuthnRequestGenerator(configuration.getHostname() + "/metadata", credential);
        }
        return eidasAuthnRequestGenerator;
    }

    private SingleSignOnServiceLocator getSingleSignOnServiceLocator() {
        if (singleSignOnServiceLocator == null) {
            singleSignOnServiceLocator = new SingleSignOnServiceLocator(getEidasMetadataResolver());
        }
        return singleSignOnServiceLocator;
    }


}
