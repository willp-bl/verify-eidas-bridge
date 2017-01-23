package uk.gov.ida.eidas.bridge.helpers.responseToVerify;

import io.dropwizard.testing.ResourceHelpers;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.junit.Test;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;

import java.io.File;
import java.security.PublicKey;

import static com.google.common.base.Throwables.propagate;
import static org.junit.Assert.assertTrue;

public class MetadataBackedEncryptionPublicKeyRetrieverTest {

    @Test
    public void shouldRetrieveKey() throws Exception {
        MetadataResolver metadataResolver = initializeMetadata();
        MetadataBackedEncryptionPublicKeyRetriever retriever = new MetadataBackedEncryptionPublicKeyRetriever(getMetadataCredentialResolver(metadataResolver));
        PublicKey key = retriever.retrieveKey("https://signin.service.gov.uk");
        assertTrue("Public key should be non-empty", key.getEncoded().length > 10);
    }

    private MetadataResolver initializeMetadata() {
        try {
            InitializationService.initialize();
            File metadataFile = new File(ResourceHelpers.resourceFilePath("metadata.xml"));
            FilesystemMetadataResolver filesystemMetadataResolver = new FilesystemMetadataResolver(metadataFile);
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();
            filesystemMetadataResolver.setParserPool(parserPool);
            filesystemMetadataResolver.setRequireValidMetadata(true);
            filesystemMetadataResolver.setId("someId");
            filesystemMetadataResolver.initialize();
            return filesystemMetadataResolver;
        } catch (ResolverException | ComponentInitializationException | InitializationException e) {
            throw propagate(e);
        }
    }

    private MetadataCredentialResolver getMetadataCredentialResolver(MetadataResolver metadataResolver) throws ComponentInitializationException {
        PredicateRoleDescriptorResolver predicateRoleDescriptorResolver = new PredicateRoleDescriptorResolver(metadataResolver);
        predicateRoleDescriptorResolver.initialize();
        MetadataCredentialResolver metadataCredentialResolver = new MetadataCredentialResolver();
        metadataCredentialResolver.setRoleDescriptorResolver(predicateRoleDescriptorResolver);
        metadataCredentialResolver.setKeyInfoCredentialResolver(DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
        metadataCredentialResolver.initialize();
        return metadataCredentialResolver;
    }
}
