package org.keycloak.testsuite.broker;

import static org.junit.Assert.assertEquals;
import static org.keycloak.models.utils.DefaultAuthenticationFlows.IDP_REVIEW_PROFILE_CONFIG_ALIAS;
import static org.keycloak.testsuite.broker.BrokerRunOnServerUtil.configurePostBrokerLoginWithOTP;
import static org.keycloak.testsuite.broker.BrokerRunOnServerUtil.disablePostBrokerLoginFlow;
import static org.keycloak.testsuite.broker.BrokerTestConstants.REALM_PROV_NAME;
import static org.keycloak.testsuite.broker.BrokerTestTools.getAuthRoot;
import static org.keycloak.testsuite.broker.BrokerTestTools.waitForPage;

import java.util.List;
import java.util.function.BiConsumer;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.authentication.authenticators.broker.IdpCreateUserIfUniqueAuthenticatorFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.ExternalKeycloakRoleToRoleMapper;
import org.keycloak.crypto.Algorithm;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;
import org.keycloak.models.utils.TimeBasedOTP;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.Assert;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude.AuthServer;
import org.keycloak.testsuite.pages.LoginConfigTotpPage;
import org.keycloak.testsuite.pages.LoginTotpPage;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;

@AuthServerContainerExclude(AuthServer.REMOTE)
public class KcOidcBrokerTest extends AbstractBrokerTest {

    @Deployment
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(UserResource.class)
                .addPackages(true, "org.keycloak.testsuite")
                .addPackages(true, "org.keycloak.admin.client.resource");
    }

    @Page
    protected LoginTotpPage loginTotpPage;

    @Page
    protected LoginConfigTotpPage totpPage;

    protected TimeBasedOTP totp = new TimeBasedOTP();

    @Override
    protected BrokerConfiguration getBrokerConfiguration() {
        return KcOidcBrokerConfiguration.INSTANCE;
    }

    @Override
    protected Iterable<IdentityProviderMapperRepresentation> createIdentityProviderMappers() {
        IdentityProviderMapperRepresentation attrMapper1 = new IdentityProviderMapperRepresentation();
        attrMapper1.setName("manager-role-mapper");
        attrMapper1.setIdentityProviderMapper(ExternalKeycloakRoleToRoleMapper.PROVIDER_ID);
        attrMapper1.setConfig(ImmutableMap.<String,String>builder()
                .put("external.role", ROLE_MANAGER)
                .put("role", ROLE_MANAGER)
                .build());

        IdentityProviderMapperRepresentation attrMapper2 = new IdentityProviderMapperRepresentation();
        attrMapper2.setName("user-role-mapper");
        attrMapper2.setIdentityProviderMapper(ExternalKeycloakRoleToRoleMapper.PROVIDER_ID);
        attrMapper2.setConfig(ImmutableMap.<String,String>builder()
                .put("external.role", ROLE_USER)
                .put("role", ROLE_USER)
                .build());

        return Lists.newArrayList(attrMapper1, attrMapper2);
    }

    @Test
    public void loginFetchingUserFromUserEndpoint() {
        RealmResource realm = realmsResouce().realm(bc.providerRealmName());
        ClientsResource clients = realm.clients();
        ClientRepresentation brokerApp = clients.findByClientId("brokerapp").get(0);

        try {
            IdentityProviderResource identityProviderResource = realmsResouce().realm(bc.consumerRealmName()).identityProviders().get(bc.getIDPAlias());
            IdentityProviderRepresentation idp = identityProviderResource.toRepresentation();

            idp.getConfig().put(OIDCIdentityProviderConfig.JWKS_URL, getAuthRoot(suiteContext) + "/auth/realms/" + REALM_PROV_NAME + "/protocol/openid-connect/certs");
            identityProviderResource.update(idp);

            brokerApp.getAttributes().put(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG, Algorithm.RS256);
            brokerApp.getAttributes().put("validateSignature", Boolean.TRUE.toString());
            clients.get(brokerApp.getId()).update(brokerApp);

            driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

            log.debug("Clicking social " + bc.getIDPAlias());
            loginPage.clickSocial(bc.getIDPAlias());

            waitForPage(driver, "log in to", true);

            Assert.assertTrue("Driver should be on the provider realm page right now",
                    driver.getCurrentUrl().contains("/auth/realms/" + bc.providerRealmName() + "/"));

            log.debug("Logging in");
            loginPage.login(bc.getUserLogin(), bc.getUserPassword());

            waitForPage(driver, "update account information", false);

            updateAccountInformationPage.assertCurrent();
            Assert.assertTrue("We must be on correct realm right now",
                    driver.getCurrentUrl().contains("/auth/realms/" + bc.consumerRealmName() + "/"));

            log.debug("Updating info on updateAccount page");
            updateAccountInformationPage.updateAccountInformation(bc.getUserLogin(), bc.getUserEmail(), "Firstname", "Lastname");

            UsersResource consumerUsers = adminClient.realm(bc.consumerRealmName()).users();

            int userCount = consumerUsers.count();
            Assert.assertTrue("There must be at least one user", userCount > 0);

            List<UserRepresentation> users = consumerUsers.search("", 0, userCount);

            boolean isUserFound = false;
            for (UserRepresentation user : users) {
                if (user.getUsername().equals(bc.getUserLogin()) && user.getEmail().equals(bc.getUserEmail())) {
                    isUserFound = true;
                    break;
                }
            }

            Assert.assertTrue("There must be user " + bc.getUserLogin() + " in realm " + bc.consumerRealmName(),
                    isUserFound);
        } finally {
            brokerApp.getAttributes().put(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG, null);
            brokerApp.getAttributes().put("validateSignature", Boolean.FALSE.toString());
            clients.get(brokerApp.getId()).update(brokerApp);
        }
    }


    // KEYCLOAK-12986
    @Test
    public void testPostBrokerLoginFlowWithOTP_bruteForceEnabled() {
        updateExecutions(KcOidcBrokerTest::disableUpdateProfileOnFirstLogin);
        testingClient.server(bc.consumerRealmName()).run(configurePostBrokerLoginWithOTP(bc.getIDPAlias()));

        // Enable brute force protector in consumer realm
        RealmResource realm = adminClient.realm(bc.consumerRealmName());
        RealmRepresentation consumerRealmRep = realm.toRepresentation();
        consumerRealmRep.setBruteForceProtected(true);
        consumerRealmRep.setFailureFactor(2);
        consumerRealmRep.setMaxDeltaTimeSeconds(20);
        consumerRealmRep.setMaxFailureWaitSeconds(100);
        consumerRealmRep.setWaitIncrementSeconds(5);
        realm.update(consumerRealmRep);

        try {
            driver.navigate().to(getAccountUrl(bc.consumerRealmName()));

            logInWithBroker(bc);

            totpPage.assertCurrent();
            String totpSecret = totpPage.getTotpSecret();
            totpPage.configure(totp.generateTOTP(totpSecret));
            assertNumFederatedIdentities(realm.users().search(bc.getUserLogin()).get(0).getId(), 1);
            logoutFromRealm(bc.consumerRealmName());

            logInWithBroker(bc);

            loginTotpPage.assertCurrent();

            // Login for 2 times with incorrect TOTP. This should temporarily disable the user
            loginTotpPage.login("bad-totp");
            Assert.assertEquals("Invalid authenticator code.", loginTotpPage.getError());

            loginTotpPage.login("bad-totp");
            Assert.assertEquals("Invalid authenticator code.", loginTotpPage.getError());

            // Login with valid TOTP. I should not be able to login
            loginTotpPage.login(totp.generateTOTP(totpSecret));
            Assert.assertEquals("Invalid authenticator code.", loginTotpPage.getError());

            // Clear login failures
            String userId = ApiUtil.findUserByUsername(realm, bc.getUserLogin()).getId();
            realm.attackDetection().clearBruteForceForUser(userId);

            loginTotpPage.login(totp.generateTOTP(totpSecret));
            waitForAccountManagementTitle();
            logoutFromRealm(bc.consumerRealmName());
        } finally {
            testingClient.server(bc.consumerRealmName()).run(disablePostBrokerLoginFlow(bc.getIDPAlias()));

            // Disable brute force protector
            consumerRealmRep = realm.toRepresentation();
            consumerRealmRep.setBruteForceProtected(false);
            realm.update(consumerRealmRep);
        }
    }

    private void updateExecutions(BiConsumer<AuthenticationExecutionInfoRepresentation, AuthenticationManagementResource> action) {
        AuthenticationManagementResource flows = adminClient.realm(bc.consumerRealmName()).flows();

        for (AuthenticationExecutionInfoRepresentation execution : flows.getExecutions(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW)) {
            action.accept(execution, flows);
        }
    }

    private static void disableUpdateProfileOnFirstLogin(AuthenticationExecutionInfoRepresentation execution, AuthenticationManagementResource flows) {
        if (execution.getProviderId() != null && execution.getProviderId().equals(IdpCreateUserIfUniqueAuthenticatorFactory.PROVIDER_ID)) {
            execution.setRequirement(AuthenticationExecutionModel.Requirement.ALTERNATIVE.name());
            flows.updateExecutions(DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW, execution);
        } else if (execution.getAlias() != null && execution.getAlias().equals(IDP_REVIEW_PROFILE_CONFIG_ALIAS)) {
            AuthenticatorConfigRepresentation config = flows.getAuthenticatorConfig(execution.getAuthenticationConfig());
            config.getConfig().put("update.profile.on.first.login", IdentityProviderRepresentation.UPFLM_OFF);
            flows.updateAuthenticatorConfig(config.getId(), config);
        }
    }

    private void assertNumFederatedIdentities(String userId, int expected) {
        assertEquals(expected, adminClient.realm(bc.consumerRealmName()).users().get(userId).getFederatedIdentity().size());
    }

    private void waitForAccountManagementTitle() {
        boolean isProduct = adminClient.serverInfo().getInfo().getProfileInfo().getName().equals("product");
        String title = isProduct ? "rh-sso account management" : "keycloak account management";
        waitForPage(driver, title, true);
    }

}
