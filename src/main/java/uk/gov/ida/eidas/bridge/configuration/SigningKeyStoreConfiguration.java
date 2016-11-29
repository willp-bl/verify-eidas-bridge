package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Throwables;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class SigningKeyStoreConfiguration {
    @JsonProperty
    @NotNull
    @Valid
    private String base64Value;

    @JsonProperty
    @NotNull
    @Valid
    private String password;

    @JsonProperty
    @NotNull
    @Valid
    private String type = KeyStore.getDefaultType();

    public String getPassword() {
        return password;
    }

    public KeyStore getKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(new ByteArrayInputStream(Base64.decode(base64Value)), password.toCharArray());
            return keyStore;
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException | CertificateException | Base64DecodingException e) {
            throw Throwables.propagate(e);
        }
    }
}
