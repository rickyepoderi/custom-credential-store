package es.rickyepoderi.ccs;

import java.util.Collections;
import org.wildfly.security.WildFlyElytronBaseProvider;

/**
 * <p>The provider that defines the <em>CustomCredentialStoreProvider</em>
 * type.</p>
 *
 * <p>CLI commands to install it into wildfly:</p>
 *
 * <pre>
 * module add --name=es.rickyepoderi.ccs --resources=/path/to/custom-credential-store-0.0.1.jar --dependencies=org.wildfly.security.elytron
 * /subsystem=elytron/provider-loader=ccs:add(module=es.rickyepoderi.ccs)
 * /subsystem=elytron/credential-store=ccs:add(providers=ccs, credential-reference={clear-text=XXXXXXX}, location=custom.properties, relative-to=jboss.server.config.dir, type=CustomCredentialStoreProvider, create=true)
 * /subsystem=elytron/credential-store=ccs:add-alias(alias=alias1, secret-value=supersecretvalue)
 * </pre>
 *
 * @author rickyepoderi
 */
public class CustomCredentialStoreProvider extends WildFlyElytronBaseProvider {

    private static final CustomCredentialStoreProvider INSTANCE = new CustomCredentialStoreProvider();

    public CustomCredentialStoreProvider() {
        super("CustomCredentialStoreProvider", "0.1", "Custom CredentialStore Provider");
        putService(new Service(this, "CredentialStore", "CustomCredentialStoreProvider",
                "es.rickyepoderi.ccs.CustomCredentialStore", Collections.<String>emptyList(),
                Collections.<String, String>emptyMap()));
    }

    public static CustomCredentialStoreProvider getInstance() {
        return INSTANCE;
    }
}
