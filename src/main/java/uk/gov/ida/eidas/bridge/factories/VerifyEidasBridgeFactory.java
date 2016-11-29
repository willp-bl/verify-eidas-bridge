package uk.gov.ida.eidas.bridge.factories;

import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.BasicRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.configuration.SigningKeyStoreConfiguration;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestFormGenerator;
import uk.gov.ida.eidas.bridge.helpers.AuthnRequestHandler;
import uk.gov.ida.eidas.bridge.helpers.EidasAuthnRequestGenerator;
import uk.gov.ida.eidas.bridge.helpers.ResponseHandler;
import uk.gov.ida.eidas.bridge.helpers.SingleSignOnServiceLocator;
import uk.gov.ida.eidas.bridge.resources.BridgeMetadataResource;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.eidas.bridge.resources.VerifyAuthnRequestResource;
import uk.gov.ida.saml.core.api.CoreTransformersFactory;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.deserializers.validators.SizeValidator;
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
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

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

    public VerifyEidasBridgeFactory(
        Environment environment,
        BridgeConfiguration configuration) {
        this.environment = environment;
        this.verifyMetadataConfiguration = configuration.getVerifyMetadataConfiguration();
        this.eidasMetadataConfiguration = configuration.getEidasMetadataConfiguration();
        this.configuration = configuration;
    }

    public AuthnRequestHandler getAuthnRequestHandler() throws ComponentInitializationException {
        StringSizeValidator stringSizeValidator = new StringSizeValidator();
        AuthnRequestSizeValidator authnRequestSizeValidator = new AuthnRequestSizeValidator(stringSizeValidator);
        StringToOpenSamlObjectTransformer<AuthnRequest> stringToAuthnRequest =
            coreTransformersFactory.getStringtoOpenSamlObjectTransformer(authnRequestSizeValidator);
        return new AuthnRequestHandler(
                this.verifyMetadataConfiguration,
                getMetadataBackedSignatureValidator(getVerifyMetadataResolver()),
                stringToAuthnRequest);
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
        return new AuthnRequestFormGenerator(
            getEidasAuthnRequestGenerator(),
            getEidasSingleSignOnServiceLocator(),
            new XmlObjectToBase64EncodedStringTransformer(),
            configuration.getEidasNodeEntityId());
    }

    public VerifyAuthnRequestResource getVerifyAuthnRequestResource() throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        AuthnRequestHandler authnRequestHandler = this.getAuthnRequestHandler();
        AuthnRequestFormGenerator authnRequestFormGenerator = this.getAuthnRequestFormGenerator();
        return new VerifyAuthnRequestResource(authnRequestHandler, authnRequestFormGenerator);
    }

    public BridgeMetadataResource getBridgeMetadataResource() throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore signingKeyStore = configuration.getSigningKeyStoreConfiguration().getKeyStore();
        java.security.cert.Certificate certificate = signingKeyStore.getCertificate(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS);
        PrivateKey privateKey = (PrivateKey) signingKeyStore.getKey(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS, "fooBar".toCharArray());
        BridgeMetadataFactory bridgeMetadataFactory = new BridgeMetadataFactory(configuration.getHostname(), certificate, privateKey, configuration.getBridgeEntityId());
        return bridgeMetadataFactory.getBridgeMetadataResource();
    }

    public EidasResponseResource getEidasResponseResource() throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        StringToOpenSamlObjectTransformer<Response> stringToResponse = coreTransformersFactory.getStringtoOpenSamlObjectTransformer((SizeValidator) input -> { });
        ResponseHandler responseHandler = new ResponseHandler(stringToResponse, this.getMetadataBackedSignatureValidator(getEidasMetadataResolver()), configuration.getEidasNodeEntityId());
        return new EidasResponseResource(responseHandler);
    }

    private MetadataResolver getMetadataResolver(MetadataConfiguration metadataConfiguration) {
        String trustStorePath = metadataConfiguration.getTrustStorePath();
        InputStream keyStoreResource = getClass().getClassLoader().getResourceAsStream(trustStorePath);
        KeyStore keyStore = new KeyStoreLoader().load(
            keyStoreResource,
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

    private MetadataBackedSignatureValidator getMetadataBackedSignatureValidator(MetadataResolver metadataResolver) throws ComponentInitializationException {
        BasicRoleDescriptorResolver basicRoleDescriptorResolver = new BasicRoleDescriptorResolver(metadataResolver);
        basicRoleDescriptorResolver.initialize();
        MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
        metadataCredentialResolver.setRoleDescriptorResolver(basicRoleDescriptorResolver);
        metadataCredentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
        metadataCredentialResolver.initialize();
        ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine = new ExplicitKeySignatureTrustEngine(
            metadataCredentialResolver, DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
        );
        return MetadataBackedSignatureValidator.withoutCertificateChainValidation(explicitKeySignatureTrustEngine);
    }


    private EidasAuthnRequestGenerator getEidasAuthnRequestGenerator() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        SigningKeyStoreConfiguration signingKeyStoreConfiguration = configuration.getSigningKeyStoreConfiguration();
        KeyStore keyStore = signingKeyStoreConfiguration.getKeyStore();
        PublicKey publicKey = keyStore.getCertificate(SIGNING_KEY_ALIAS).getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(SIGNING_KEY_ALIAS, signingKeyStoreConfiguration.getPassword().toCharArray());
        BasicCredential credential = new BasicCredential(publicKey, privateKey);
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        KeyStore signingKeyStore = configuration.getSigningKeyStoreConfiguration().getKeyStore();
        java.security.cert.Certificate certificate = signingKeyStore.getCertificate(VerifyEidasBridgeFactory.SIGNING_KEY_ALIAS);
        BasicX509Credential x509SigningCredential = new BasicX509Credential((X509Certificate) certificate);

        return new EidasAuthnRequestGenerator(configuration.getHostname() + "/metadata", configuration.getEidasNodeEntityId(), credential, x509SigningCredential, keyInfoGenerator, getEidasSingleSignOnServiceLocator());
    }

    private SingleSignOnServiceLocator getEidasSingleSignOnServiceLocator() {
        return new SingleSignOnServiceLocator(getEidasMetadataResolver());
    }
}
