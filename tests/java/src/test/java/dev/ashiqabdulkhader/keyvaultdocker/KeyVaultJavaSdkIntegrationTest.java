package dev.ashiqabdulkhader.keyvaultdocker;

import com.azure.core.credential.TokenCredential;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.SecretServiceVersion;
import com.azure.security.keyvault.secrets.models.DeletedSecret;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyVaultJavaSdkIntegrationTest {
    private static final String HOST = requiredEnv("KEYVAULT_EMULATOR_HOST");
    private static final String PORT = requiredEnv("KEYVAULT_EMULATOR_PORT");
    private static final String TENANT_ID = requiredEnv("KEYVAULT_TENANT_ID");
    private static final String CLIENT_ID = requiredEnv("KEYVAULT_CLIENT_ID");
    private static final String CLIENT_SECRET = requiredEnv("KEYVAULT_CLIENT_SECRET");

    @Test
    void secretCrudWorksAgainstTheEmulator() throws Exception {
        SecretClient client = createClient();
        String secretName = "java-crud-" + UUID.randomUUID();

        KeyVaultSecret created = client.setSecret(secretName, "hello-from-java");
        KeyVaultSecret fetched = client.getSecret(secretName);
        List<String> names = new ArrayList<>();
        client.listPropertiesOfSecrets().forEach(secret -> names.add(secret.getName()));
        DeletedSecret deleted = client.beginDeleteSecret(secretName).poll().getValue();

        assertEquals("hello-from-java", created.getValue());
        assertEquals("hello-from-java", fetched.getValue());
        assertTrue(names.contains(secretName));
        assertEquals(secretName, deleted.getName());
    }

    @Test
    void versioningAndRecoveryWorkAgainstTheEmulator() throws Exception {
        SecretClient client = createClient();
        String secretName = "java-versions-" + UUID.randomUUID();

        KeyVaultSecret first = client.setSecret(secretName, "v1");
        KeyVaultSecret second = client.setSecret(secretName, "v2");
        List<String> versions = new ArrayList<>();
        client.listPropertiesOfSecretVersions(secretName).forEach(secret -> versions.add(secret.getVersion()));

        DeletedSecret deleted = client.beginDeleteSecret(secretName).poll().getValue();
        List<String> deletedNames = new ArrayList<>();
        client.listDeletedSecrets().forEach(secret -> deletedNames.add(secret.getName()));
        KeyVaultSecret recovered = client.beginRecoverDeletedSecret(secretName).poll().getValue();

        SecretProperties latest = client.getSecret(secretName).getProperties();

        assertTrue(versions.contains(first.getProperties().getVersion()));
        assertTrue(versions.contains(second.getProperties().getVersion()));
        assertEquals(secretName, deleted.getName());
        assertTrue(deletedNames.contains(secretName));
        assertEquals(secretName, recovered.getName());
        assertFalse(latest.getVersion().isBlank());
    }

    private static SecretClient createClient() throws Exception {
        HttpClient httpClient = insecureHttpClient();
        TokenCredential credential = new ClientSecretCredentialBuilder()
            .tenantId(TENANT_ID)
            .clientId(CLIENT_ID)
            .clientSecret(CLIENT_SECRET)
            .authorityHost(authorityHost())
            .disableInstanceDiscovery()
            .additionallyAllowedTenants("*")
            .httpClient(httpClient)
            .build();

        return new SecretClientBuilder()
            .vaultUrl(vaultUrl())
            .credential(credential)
            .httpClient(httpClient)
            .disableChallengeResourceVerification()
            .serviceVersion(SecretServiceVersion.V7_5)
            .buildClient();
    }

    private static HttpClient insecureHttpClient() throws Exception {
        reactor.netty.http.client.HttpClient reactorClient = reactor.netty.http.client.HttpClient.create()
            .secure(ssl -> ssl.sslContext(
                SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE)
            ));
        return new NettyAsyncHttpClientBuilder(reactorClient).build();
    }

    private static String authorityHost() {
        return "https://" + HOST + ":" + PORT;
    }

    private static String vaultUrl() {
        return "https://" + HOST + ":" + PORT;
    }

    private static String requiredEnv(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing environment variable: " + key);
        }
        return value;
    }
}
