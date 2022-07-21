package es.rickyepoderi.ccs;

import java.io.File;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Map;
import java.util.ServiceLoader;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStore.ProtectionParameter;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.WildFlyElytronPasswordProvider;
import org.wildfly.security.password.interfaces.ClearPassword;
import org.wildfly.security.password.spec.ClearPasswordSpec;

/**
 *
 * @author rickyepoderi
 */
public class CustomCredentialStoreProviderTest {

    private static final Provider pwdProvider = WildFlyElytronPasswordProvider.getInstance();

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @BeforeClass
    public static void setup() throws Exception {
        Security.addProvider(pwdProvider);
    }

    @AfterClass
    public static void remove() {
        Security.removeProvider(pwdProvider.getName());
    }

    @Test
    public void testServiceLoader() {
        ServiceLoader<Provider> loader = ServiceLoader.load(Provider.class);
        for (Provider p: loader) {
            if (p instanceof CustomCredentialStoreProvider) {
                return;
            }
        }
        Assert.fail("CustomCredentialStoreProvider was not found");
    }

    @Test
    public void testProvider() throws Exception {
        CustomCredentialStoreProvider prov = CustomCredentialStoreProvider.getInstance();
        Assert.assertNotNull(prov);
        CredentialStore store = CredentialStore.getInstance("CustomCredentialStoreProvider", prov);
        Assert.assertNotNull(store);
        ProtectionParameter param = new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                        ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "PBEPasswordToUse123".toCharArray()))));
        final File propsFile = tempFolder.newFile("store1.properties");
        Map<String, String> attrs = Map.of(CustomCredentialStore.CREATE, "true",
                CustomCredentialStore.LOCATION, propsFile.getAbsolutePath());

        store.initialize(attrs, param);

        store.store("alias1", createCredentialFromPassword("supersecretvalue".toCharArray()));
        Assert.assertEquals(Collections.singleton("alias1"), store.getAliases());
        Assert.assertEquals("supersecretvalue", new String(getPasswordFromCredential(store.retrieve("alias1", PasswordCredential.class))));
        Assert.assertTrue(Files.size(propsFile.toPath()) > 0);
        store.remove("alias1", PasswordCredential.class);
        Assert.assertEquals(Collections.<String>emptySet(), store.getAliases());
    }

    @Test
    public void testProviderOtherAlgorithm() throws Exception {
        CustomCredentialStoreProvider prov = CustomCredentialStoreProvider.getInstance();
        Assert.assertNotNull(prov);
        CredentialStore store = CredentialStore.getInstance("CustomCredentialStoreProvider", prov);
        Assert.assertNotNull(store);
        ProtectionParameter param = new CredentialStore.CredentialSourceProtectionParameter(
                IdentityCredentials.NONE.withCredential(new PasswordCredential(
                        ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, "PBEPasswordToUse123".toCharArray()))));
        final File propsFile = tempFolder.newFile("store2.properties");
        Map<String, String> attrs = Map.of(CustomCredentialStore.CREATE, "true",
                CustomCredentialStore.LOCATION, propsFile.getAbsolutePath(),
                CustomCredentialStore.PBE_ALGORITHM, "PBEWithMD5AndTripleDES");

        store.initialize(attrs, param);

        store.store("alias1", createCredentialFromPassword("supersecretvalue".toCharArray()));
        Assert.assertEquals(Collections.singleton("alias1"), store.getAliases());
        Assert.assertEquals("supersecretvalue", new String(getPasswordFromCredential(store.retrieve("alias1", PasswordCredential.class))));
        Assert.assertTrue(Files.size(propsFile.toPath()) > 0);
        store.remove("alias1", PasswordCredential.class);
        Assert.assertEquals(Collections.<String>emptySet(), store.getAliases());
    }

    private PasswordCredential createCredentialFromPassword(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ClearPassword.ALGORITHM_CLEAR);
        return new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(password)));
    }

    private char[] getPasswordFromCredential(PasswordCredential passwordCredential) {
        return passwordCredential.getPassword().castAndApply(ClearPassword.class, ClearPassword::getPassword);
    }
}
