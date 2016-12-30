package uk.gov.ida.eidas.bridge.factories;

import com.google.common.collect.ImmutableSet;
import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.duplicates.AttributeFactory;
import uk.gov.ida.duplicates.SamlResponseAssertionEncrypter;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.configuration.KeyStoreConfiguration;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.AssertionConsumerServiceLocator;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.AssertionSubjectGenerator;
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.AuthnRequestFormGenerator;
import uk.gov.ida.eidas.bridge.helpers.requestFromVerify.AuthnRequestHandler;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.AuthnStatementAssertionGenerator;
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.EidasAuthnRequestGenerator;
import uk.gov.ida.eidas.bridge.helpers.responseFromEidas.EidasIdentityAssertionUnmarshaller;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.MatchingDatasetAssertionGenerator;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.MetadataBackedEncryptionPublicKeyRetriever;
import uk.gov.ida.eidas.bridge.helpers.responseFromEidas.ResponseHandler;
import uk.gov.ida.eidas.bridge.helpers.responseFromEidas.ResponseSizeValidator;
import uk.gov.ida.eidas.bridge.helpers.SigningHelper;
import uk.gov.ida.eidas.bridge.helpers.requestToEidas.SingleSignOnServiceLocator;
import uk.gov.ida.eidas.bridge.helpers.responseToVerify.VerifyResponseGenerator;
import uk.gov.ida.eidas.bridge.resources.BridgeMetadataResource;
import uk.gov.ida.eidas.bridge.resources.EidasResponseResource;
import uk.gov.ida.eidas.bridge.resources.VerifyAuthnRequestResource;
import uk.gov.ida.saml.deserializers.OpenSamlXMLObjectUnmarshaller;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.deserializers.parser.SamlObjectParser;
import uk.gov.ida.saml.deserializers.validators.Base64StringDecoder;
import uk.gov.ida.saml.deserializers.validators.NotNullSamlStringValidator;
import uk.gov.ida.saml.dropwizard.metadata.MetadataHealthCheck;
import uk.gov.ida.saml.metadata.ExpiredCertificateMetadataFilter;
import uk.gov.ida.saml.metadata.KeyStoreLoader;
import uk.gov.ida.saml.metadata.MetadataConfiguration;
import uk.gov.ida.saml.metadata.PKIXSignatureValidationFilterProvider;
import uk.gov.ida.saml.metadata.modules.MetadataModule;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.DecrypterFactory;
import uk.gov.ida.saml.security.EncrypterFactory;
import uk.gov.ida.saml.security.EncryptionCredentialFactory;
import uk.gov.ida.saml.security.KeyStoreCredentialRetriever;
import uk.gov.ida.saml.security.MetadataBackedSignatureValidator;
import uk.gov.ida.saml.security.SamlAssertionsSignatureValidator;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;
import uk.gov.ida.saml.security.validators.encryptedelementtype.EncryptionAlgorithmValidator;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import javax.annotation.Nullable;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static java.util.Collections.singletonList;

public class VerifyEidasBridgeFactory {

    private final Environment environment;
    private final MetadataConfiguration verifyMetadataConfiguration;
    private final MetadataConfiguration eidasMetadataConfiguration;
    private final BridgeConfiguration configuration;
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

    public VerifyAuthnRequestResource getVerifyAuthnRequestResource() throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        AuthnRequestHandler authnRequestHandler = this.getAuthnRequestHandler();
        AuthnRequestFormGenerator authnRequestFormGenerator = this.getAuthnRequestFormGenerator();
        return new VerifyAuthnRequestResource(authnRequestHandler, authnRequestFormGenerator);
    }

    public BridgeMetadataResource getBridgeMetadataResource() throws UnrecoverableKeyException, CertificateEncodingException, NoSuchAlgorithmException, KeyStoreException {
        KeyStoreConfiguration signingKeyStoreConfiguration = configuration.getEidasSigningKeyStoreConfiguration();
        KeyStore signingKeyStore = signingKeyStoreConfiguration.getKeyStore();
        String signingKeyAlias = signingKeyStoreConfiguration.getAlias();
        java.security.cert.Certificate signingCertificate = signingKeyStore.getCertificate(signingKeyAlias);
        PrivateKey privateKey = (PrivateKey) signingKeyStore.getKey(signingKeyAlias, signingKeyStoreConfiguration.getPassword().toCharArray());

        KeyStoreConfiguration encryptingKeyStoreConfiguration = configuration.getEncryptingKeyStoreConfiguration();
        java.security.cert.Certificate encryptingCertificate = encryptingKeyStoreConfiguration.getKeyStore().getCertificate(encryptingKeyStoreConfiguration.getAlias());

        BridgeMetadataFactory bridgeMetadataFactory = new BridgeMetadataFactory(configuration.getHostname(), signingCertificate, encryptingCertificate, privateKey, configuration.getBridgeEntityId());
        return bridgeMetadataFactory.getBridgeMetadataResource();
    }

    public EidasResponseResource getEidasResponseResource() throws ComponentInitializationException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        StringToOpenSamlObjectTransformer<Response> stringToResponse = new StringToOpenSamlObjectTransformer<>(
                new NotNullSamlStringValidator(),
                new Base64StringDecoder(),
                new ResponseSizeValidator(),
                new OpenSamlXMLObjectUnmarshaller<>(new SamlObjectParser())
        );
        MetadataBackedSignatureValidator signatureValidator = this.getMetadataBackedSignatureValidator(getEidasMetadataResolver());
        KeyStoreConfiguration keyStoreConfiguration = configuration.getEidasSigningKeyStoreConfiguration();

        ResponseHandler responseHandler = getResponseHandler(stringToResponse, signatureValidator, keyStoreConfiguration);

        String bridgeEntityId = configuration.getBridgeEntityId();
        String verifyEntityId = configuration.getVerifyMetadataConfiguration().getExpectedEntityId();

        VerifyResponseGenerator verifyResponseGenerator = getVerifyResponseGenerator(bridgeEntityId, verifyEntityId);

        return new EidasResponseResource(
            verifyEntityId,
            new XmlObjectToBase64EncodedStringTransformer(),
            responseHandler,
            verifyResponseGenerator,
            new AssertionConsumerServiceLocator(verifyMetadataResolver));
    }

    public MetadataHealthCheck getVerifyMetadataHealthcheck() {
        return new MetadataHealthCheck(getVerifyMetadataResolver(), configuration.getVerifyMetadataConfiguration().getExpectedEntityId());
    }

    public MetadataHealthCheck getEidasMetadataHealthcheck() {
        return new MetadataHealthCheck(getEidasMetadataResolver(), configuration.getEidasMetadataConfiguration().getExpectedEntityId());
    }

    private MetadataResolver getVerifyMetadataResolver() {
        if (verifyMetadataResolver == null) {
            verifyMetadataResolver = getMetadataResolver(verifyMetadataConfiguration);
        }
        return verifyMetadataResolver;
    }

    private MetadataResolver getEidasMetadataResolver() {
        if (eidasMetadataResolver == null) {
            eidasMetadataResolver = getMetadataResolver(eidasMetadataConfiguration);
        }
        return eidasMetadataResolver;
    }

    private AuthnRequestHandler getAuthnRequestHandler() throws ComponentInitializationException {
        StringToOpenSamlObjectTransformer<AuthnRequest> stringToAuthnRequest = new StringToOpenSamlObjectTransformer<>(
            new NotNullSamlStringValidator(),
            new Base64StringDecoder(),
            new ResponseSizeValidator(),
            new OpenSamlXMLObjectUnmarshaller<>(new SamlObjectParser())
        );
        return new AuthnRequestHandler(
            this.verifyMetadataConfiguration,
            getMetadataBackedSignatureValidator(getVerifyMetadataResolver()),
            stringToAuthnRequest);
    }

    private AuthnRequestFormGenerator getAuthnRequestFormGenerator() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return new AuthnRequestFormGenerator(
            getEidasAuthnRequestGenerator(),
            getEidasSingleSignOnServiceLocator(),
            new XmlObjectToBase64EncodedStringTransformer(),
            configuration.getEidasNodeEntityId());
    }

    private VerifyResponseGenerator getVerifyResponseGenerator(String bridgeEntityId, String verifyEntityId) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {

        AttributeFactory attributeFactory = new AttributeFactory();
        AssertionSubjectGenerator assertionSubjectGenerator = new AssertionSubjectGenerator(verifyEntityId);
        SigningHelper verifySigningHelper = getVerifySigningHelper();

        MetadataBackedEncryptionPublicKeyRetriever metadataBackedEncryptionPublicKeyRetriever = new MetadataBackedEncryptionPublicKeyRetriever(getVerifyMetadataResolver());
        EncryptionCredentialFactory encryptionCredentialFactory = new EncryptionCredentialFactory(metadataBackedEncryptionPublicKeyRetriever::retrieveKey);

        return new VerifyResponseGenerator(
            bridgeEntityId,
            new MatchingDatasetAssertionGenerator(bridgeEntityId, attributeFactory, assertionSubjectGenerator, verifySigningHelper),
            new AuthnStatementAssertionGenerator(bridgeEntityId, attributeFactory, assertionSubjectGenerator, verifySigningHelper),
            new SamlResponseAssertionEncrypter(encryptionCredentialFactory, new EncrypterFactory(), requestId -> verifyEntityId),
            verifySigningHelper);
    }

    private ResponseHandler getResponseHandler(StringToOpenSamlObjectTransformer<Response> stringToResponse, MetadataBackedSignatureValidator signatureValidator, KeyStoreConfiguration keyStoreConfiguration) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        uk.gov.ida.saml.security.KeyStore samlSecurityKeyStore = new uk.gov.ida.saml.security.KeyStore(
            getSigningKeyPair(keyStoreConfiguration),
            singletonList(getEncryptingKeyPair())
        );
        SamlMessageSignatureValidator samlMessageSignatureValidator = new SamlMessageSignatureValidator(signatureValidator);
        Set<String> encryptionAlgorithmWhitelist = ImmutableSet.of(
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128_GCM,
            EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM
        );
        return new ResponseHandler(
            stringToResponse,
            configuration.getEidasNodeEntityId(),
            new SamlResponseSignatureValidator(samlMessageSignatureValidator),
            new AssertionDecrypter(new KeyStoreCredentialRetriever(samlSecurityKeyStore), new EncryptionAlgorithmValidator(encryptionAlgorithmWhitelist), new DecrypterFactory()),
            new SamlAssertionsSignatureValidator(samlMessageSignatureValidator),
            new EidasIdentityAssertionUnmarshaller());
    }

    private KeyPair getEncryptingKeyPair() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStoreConfiguration encryptingKeyStoreConfiguration = configuration.getEncryptingKeyStoreConfiguration();
        KeyStore encryptingKeyStore = encryptingKeyStoreConfiguration.getKeyStore();
        PublicKey encryptingPublicKey = encryptingKeyStore.getCertificate(encryptingKeyStoreConfiguration.getAlias()).getPublicKey();
        PrivateKey encryptingPrivateKey = (PrivateKey) encryptingKeyStore.getKey(encryptingKeyStoreConfiguration.getAlias(), encryptingKeyStoreConfiguration.getPassword().toCharArray());
        return new KeyPair(encryptingPublicKey, encryptingPrivateKey);
    }

    private KeyPair getSigningKeyPair(KeyStoreConfiguration keyStoreConfiguration) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore signingKeyStore = keyStoreConfiguration.getKeyStore();
        PublicKey publicKey = signingKeyStore.getCertificate(keyStoreConfiguration.getAlias()).getPublicKey();
        PrivateKey privateKey = (PrivateKey) signingKeyStore.getKey(keyStoreConfiguration.getAlias(), keyStoreConfiguration.getPassword().toCharArray());
        return new KeyPair(publicKey, privateKey);
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
        PredicateRoleDescriptorResolver predicateRoleDescriptorResolver = new PredicateRoleDescriptorResolver(metadataResolver);
        predicateRoleDescriptorResolver.initialize();
        MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
        metadataCredentialResolver.setRoleDescriptorResolver(predicateRoleDescriptorResolver);
        metadataCredentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
        metadataCredentialResolver.initialize();
        ExplicitKeySignatureTrustEngine explicitKeySignatureTrustEngine = new ExplicitKeySignatureTrustEngine(
            metadataCredentialResolver, DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
        );
        return MetadataBackedSignatureValidator.withoutCertificateChainValidation(explicitKeySignatureTrustEngine);
    }


    private EidasAuthnRequestGenerator getEidasAuthnRequestGenerator() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return new EidasAuthnRequestGenerator(configuration.getHostname() + "/metadata", configuration.getEidasNodeEntityId(), getEidasSigningHelper(), getEidasSingleSignOnServiceLocator());
    }

    private SingleSignOnServiceLocator getEidasSingleSignOnServiceLocator() {
        return new SingleSignOnServiceLocator(getEidasMetadataResolver());
    }

    private SigningHelper getEidasSigningHelper() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        return getSigningHelper(configuration.getEidasSigningKeyStoreConfiguration());
    }

    private SigningHelper getVerifySigningHelper() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        return getSigningHelper(configuration.getVerifySigningKeyStoreConfiguration());
    }

    private SigningHelper getSigningHelper(KeyStoreConfiguration signingKeyStoreConfiguration) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        KeyStore keyStore = signingKeyStoreConfiguration.getKeyStore();
        String signingKeyAlias = signingKeyStoreConfiguration.getAlias();
        Certificate certificate = keyStore.getCertificate(signingKeyAlias);
        PublicKey publicKey = certificate.getPublicKey();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(signingKeyAlias, signingKeyStoreConfiguration.getPassword().toCharArray());
        BasicCredential credential = new BasicCredential(publicKey, privateKey);
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();

        BasicX509Credential x509SigningCredential = new BasicX509Credential((X509Certificate) certificate);
        return new SigningHelper(credential, x509SigningCredential, keyInfoGenerator);
    }
}
