package es.rickyepoderi.ccs;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.source.CredentialSource;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.CredentialStoreSpi;
import org.wildfly.security.credential.store.UnsupportedCredentialTypeException;
import org.wildfly.security.password.interfaces.ClearPassword;

/**
 * <p>Simple example of a database credential store that adds the aliases
 * into a properties file but encrypted with a PBE secret key. The PBE
 * key is created using the protection parameter passed to the store. Inside the
 * properties file the alias is the name and the value contains the secret in
 * the format &lt;base64-encrypted-text&gt;:&lt;base64-parameters&gt;</p>
 *
 * @author rickyepoderi
 */
public class CustomCredentialStore extends CredentialStoreSpi {

    public static final String LOCATION = "location";
    public static final String CREATE = "create";
    public static final String MODIFIABLE = "modifiable";
    public static final String PBE_ALGORITHM = "pbeAlgorithm";
    public static final String SALT = "salt";
    public static final String ITERATIONS = "iterations";
    public static final String CHARSET = "charset";

    public static final String DEFAULT_SALT = "Something weird that is going to be used as salt!!!";
    public static final String DEFAULT_PBE_ALGORITHM = "PBEWithHmacSHA512AndAES_256";
    public static final String DEFAULT_CHARSET = StandardCharsets.UTF_8.name();

    private static final List<String> validAttributues = Arrays.asList(LOCATION, CREATE, MODIFIABLE, PBE_ALGORITHM, SALT, ITERATIONS, CHARSET);

    private File propertiesFile;
    private Properties properties;
    private boolean modifiable;
    private String algorithm;
    private SecretKey secretKey;
    private Charset charset;

    public CustomCredentialStore() {
        // empty
    }

    @Override
    public void initialize(Map<String, String> attributes, CredentialStore.ProtectionParameter protectionParameter,
            Provider[] providers) throws CredentialStoreException {
        if (protectionParameter == null) {
            throw new CredentialStoreException("Protection parameter is null");
        }
        validateAttribute(attributes, validAttributues);
        String location = attributes.get(LOCATION);
        if (location == null) {
            throw new CredentialStoreException("The location for the properties file is missing: " + location);
        }
        boolean create = Boolean.parseBoolean(attributes.getOrDefault(CREATE, "false"));
        modifiable = Boolean.parseBoolean(attributes.getOrDefault(MODIFIABLE, "true"));
        propertiesFile = new File(location);
        properties = new Properties();
        if (!propertiesFile.exists() && !create) {
            throw new CredentialStoreException("Location file does not exists and create is false: " + location);
        } else if (propertiesFile.exists()) {
            try (FileInputStream is = new FileInputStream(propertiesFile)) {
                properties.load(is);
            } catch (IOException e) {
                throw new CredentialStoreException("Error reading properties file " + location, e);
            }
        }
        try {
            algorithm = attributes.getOrDefault(PBE_ALGORITHM, DEFAULT_PBE_ALGORITHM);
            int iterations = Integer.parseInt(attributes.getOrDefault(ITERATIONS, "1000"));
            String salt = attributes.getOrDefault(SALT, DEFAULT_SALT);
            charset = Charset.forName(attributes.getOrDefault(CHARSET, DEFAULT_CHARSET));
            secretKey = createSecretKey(convertProtectionParameter(protectionParameter), algorithm, salt, iterations);
        } catch (NumberFormatException | NoSuchAlgorithmException | InvalidKeySpecException | CredentialStoreException e) {
            throw new CredentialStoreException("Error creating the secretkey for encryption", e);
        }
    }

    @Override
    public boolean isModifiable() {
        return modifiable;
    }

    @Override
    public void store(String alias, Credential credential, CredentialStore.ProtectionParameter protectionParameter)
            throws CredentialStoreException, UnsupportedCredentialTypeException {
        final char[] chars = credential.castAndApply(PasswordCredential.class,
                c -> c.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword));
        if (chars == null) {
            throw new UnsupportedCredentialTypeException("Only clear passwords allowed");
        }
        String value = encrypt(new String(chars));
        putInProperties(alias, value);
    }

    @Override
    public <C extends Credential> C retrieve(String alias, Class<C> credentialType, String credentialAlgorithm,
            AlgorithmParameterSpec parameterSpec, CredentialStore.ProtectionParameter protectionParameter) throws CredentialStoreException {
        if (!credentialType.isAssignableFrom(PasswordCredential.class)) {
            return null;
        }
        if (credentialAlgorithm != null && !credentialAlgorithm.equals(ClearPassword.ALGORITHM_CLEAR)) {
            return null;
        }
        if (parameterSpec != null) {
            return null;
        }
        String value = getFromProperties(alias);
        if (value == null) {
            return null;
        }
        String secret = decrypt(value);
        return credentialType.cast(new PasswordCredential(ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret.toCharArray())));
    }

    @Override
    public void remove(String alias, Class<? extends Credential> credentialType, String credentialAlgorithm,
            AlgorithmParameterSpec parameterSpec) throws CredentialStoreException {
        if (!modifiable) {
            throw new CredentialStoreException("Not modifiable store!");
        }
        if (!credentialType.isAssignableFrom(PasswordCredential.class)) {
            return;
        }
        if (credentialAlgorithm != null && !credentialAlgorithm.equals(ClearPassword.ALGORITHM_CLEAR)) {
            return;
        }
        if (parameterSpec != null) {
            return;
        }
        removeFromProperties(alias);
    }

    @Override
    public Set<String> getAliases() throws UnsupportedOperationException, CredentialStoreException {
        return getNamesFromProperties();
    }

    @Override
    public void flush() throws CredentialStoreException {
        saveProperties();
    }

    //
    // private methods
    //

    private SecretKey createSecretKey(String password, String algorithm, String salt, int iterations)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        final PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(charset), iterations);
        return factory.generateSecret(keySpec);
    }

    private String convertProtectionParameter(final CredentialStore.ProtectionParameter protectionParameter)
            throws CredentialStoreException {
        if (protectionParameter instanceof CredentialStore.CredentialSourceProtectionParameter) {
            final CredentialSource credentialSource = ((CredentialStore.CredentialSourceProtectionParameter) protectionParameter).getCredentialSource();
            try {
                return credentialSource.applyToCredential(PasswordCredential.class, c -> c.getPassword().castAndApply(ClearPassword.class, p -> new String(p.getPassword())));
            } catch (IOException e) {
                throw new CredentialStoreException(e);
            }
        } else {
            throw new CredentialStoreException("Invalid protection parameter");
        }
    }

    private String encrypt(String value) throws CredentialStoreException {
        try {
            final Cipher cipherEncrypt = Cipher.getInstance(algorithm);
            cipherEncrypt.init(Cipher.ENCRYPT_MODE, secretKey);
            final byte[] ciphertext = cipherEncrypt.doFinal(value.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder encoder = Base64.getEncoder();
            return encoder.encodeToString(ciphertext) + ":"
                    + encoder.encodeToString(cipherEncrypt.getParameters().getEncoded());
        } catch (IOException | GeneralSecurityException e) {
            throw new CredentialStoreException(e);
        }
    }

    private String decrypt(String value) throws CredentialStoreException {
        try {
            String[] parts = value.split(":");
            if (parts.length != 2) {
                throw new CredentialStoreException("Invalid value to decrypt, it should be <base64-encrypted-text>:<base64-parameters>.");
            }
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] ciphertext = decoder.decode(parts[0]);
            byte[] paramsEncoded = decoder.decode(parts[1]);
            final Cipher cipherDecrypt = Cipher.getInstance(algorithm);
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(algorithm);
            algorithmParameters.init(paramsEncoded);
            cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameters);
            return new String(cipherDecrypt.doFinal(ciphertext), charset);
        } catch (IOException | GeneralSecurityException e) {
            throw new CredentialStoreException(e);
        }
    }

    //
    // synched methods to manage the properties and underlaying file
    //

    private synchronized Set<String> getNamesFromProperties() throws CredentialStoreException {
        return properties.stringPropertyNames();
    }

    private synchronized void putInProperties(String alias, String value) throws CredentialStoreException {
        if (properties.contains(alias)) {
            throw new CredentialStoreException("Alias is already present in the store: " + alias);
        }
        properties.put(alias, value);
        saveProperties();
    }

    private synchronized String getFromProperties(String alias) throws CredentialStoreException {
        return (String) properties.get(alias);
    }

    private synchronized void removeFromProperties(String alias) throws CredentialStoreException {
        if (properties.remove(alias) != null) {
            saveProperties();
        }
    }

    private synchronized void saveProperties() throws CredentialStoreException {
        try (FileOutputStream os = new FileOutputStream(propertiesFile)) {
            properties.store(os, null);
        } catch (IOException e) {
            throw new CredentialStoreException(e);
        }
    }
}
