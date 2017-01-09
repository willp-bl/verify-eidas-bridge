package uk.gov.ida.eidas.bridge.testhelpers;

import com.google.common.base.Throwables;
import org.apache.xml.security.utils.Base64;
import uk.gov.ida.common.shared.security.X509CertificateFactory;
import uk.gov.ida.saml.core.test.TestCertificateStrings;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class TestSigningKeyStoreProvider {

    private static final String KEYSTORE_TYPE = "PKCS12";

    private static KeyStore getKeyStore(String alias, String password) {
        try {
            Certificate[] certificates = {new X509CertificateFactory().createCertificate(TestCertificateStrings.TEST_PUBLIC_CERT)};
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
            keyStore.load(null, null);

            byte[] base64DecodedPem = Base64.decode(TestCertificateStrings.TEST_PRIVATE_KEY);

            // http://stackoverflow.com/a/6164414/1344760
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(base64DecodedPem);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(pkcs8EncodedKeySpec);

            String MYPBEALG = "PBEWithSHA1AndDESede";

            int count = 20;// hash iteration count
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[8];
            random.nextBytes(salt);

            // Create PBE parameter set
            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, count);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance(MYPBEALG);
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            Cipher pbeCipher = Cipher.getInstance(MYPBEALG);

            // Initialize PBE Cipher with key and parameters
            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            // Encrypt the encoded Private Key with the PBE key
            byte[] ciphertext = pbeCipher.doFinal(privateKey.getEncoded());

            // Now construct  PKCS #8 EncryptedPrivateKeyInfo object
            AlgorithmParameters algparms = AlgorithmParameters.getInstance(MYPBEALG);
            algparms.init(pbeParamSpec);
            EncryptedPrivateKeyInfo encinfo = new EncryptedPrivateKeyInfo(algparms, ciphertext);

            keyStore.setKeyEntry(alias, encinfo.getEncoded(), certificates);
            return keyStore;
        } catch (Exception e) {
            throw Throwables.propagate(e);
        }
    }

    public static String getBase64EncodedKeyStore(String alias, String password)
    {
        return toBase64String(getKeyStore(alias, password), password);
    }

    public static String getBase64EncodedTrustStore(String cert, String password)
    {

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            X509Certificate certificate = new X509CertificateFactory().createCertificate(cert);
            keyStore.setCertificateEntry("cert", certificate);
            return toBase64String(keyStore, password);
        } catch (Exception e) {
            throw Throwables.propagate(e);
        }
    }

    private static String toBase64String(KeyStore keyStore, String password) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            keyStore.store(baos, password.toCharArray());
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
        return Base64.encode(baos.toByteArray());
    }
}
