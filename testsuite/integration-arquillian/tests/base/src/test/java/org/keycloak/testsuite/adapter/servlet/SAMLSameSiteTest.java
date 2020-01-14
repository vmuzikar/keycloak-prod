package org.keycloak.testsuite.adapter.servlet;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.adapter.AbstractServletsAdapterTest;
import org.keycloak.testsuite.adapter.page.Employee2Servlet;
import org.keycloak.testsuite.arquillian.annotation.AppServerContainer;
import org.keycloak.testsuite.arquillian.annotation.AuthServerContainerExclude;
import org.keycloak.testsuite.updaters.ClientAttributeUpdater;
import org.keycloak.testsuite.utils.arquillian.ContainerConstants;
import org.keycloak.testsuite.utils.io.IOUtil;
import org.openqa.selenium.By;

import javax.ws.rs.core.UriBuilder;
import java.util.Collections;
import java.util.List;

import static org.keycloak.testsuite.arquillian.AppServerTestEnricher.getAppServerContextRoot;
import static org.keycloak.testsuite.auth.page.AuthRealm.SAMLSERVLETDEMO;
import static org.keycloak.testsuite.saml.AbstractSamlTest.SAML_CLIENT_ID_EMPLOYEE_2;
import static org.keycloak.testsuite.util.URLAssert.assertCurrentUrlStartsWith;
import static org.keycloak.testsuite.util.WaitUtils.waitForPageToLoad;
import static org.keycloak.testsuite.util.WaitUtils.waitUntilElement;

/**
 * @author mhajas
 */
@AppServerContainer(ContainerConstants.APP_SERVER_UNDERTOW)
@AppServerContainer(ContainerConstants.APP_SERVER_WILDFLY)
@AppServerContainer(ContainerConstants.APP_SERVER_WILDFLY_DEPRECATED)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP6)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP71)
@AuthServerContainerExclude(AuthServerContainerExclude.AuthServer.REMOTE)
public class SAMLSameSiteTest extends AbstractServletsAdapterTest {
    private static final String NIP_IO_URL = "app-saml-127-0-0-1.nip.io";
    private static final String NIP_IO_EMPLOYEE2_URL = getAppServerContextRoot().replace("localhost", NIP_IO_URL) + "/employee2/";

    @Deployment(name = Employee2Servlet.DEPLOYMENT_NAME)
    protected static WebArchive employee2() {
        return samlServletDeployment(Employee2Servlet.DEPLOYMENT_NAME, SendUsernameServlet.class);
    }

    @Page
    protected Employee2Servlet employee2ServletPage;

    @Override
    public void addAdapterTestRealms(List<RealmRepresentation> testRealms) {
        testRealms.add(IOUtil.loadRealm("/adapter-test/keycloak-saml/testsaml.json"));
    }

    @Override
    public void setDefaultPageUriParameters() {
        super.setDefaultPageUriParameters();
        testRealmSAMLPostLoginPage.setAuthRealm(SAMLSERVLETDEMO);
    }

    @Test
    public void samlWorksWithSameSiteCookieTest() {
        getCleanup(SAMLSERVLETDEMO).addCleanup(ClientAttributeUpdater.forClient(adminClient, SAMLSERVLETDEMO, SAML_CLIENT_ID_EMPLOYEE_2)
                .setRedirectUris(Collections.singletonList(NIP_IO_EMPLOYEE2_URL + "*"))
                .setAdminUrl(NIP_IO_EMPLOYEE2_URL + "saml")
                .update());

        // Navigate to url with nip.io to trick browser the adapter lives on different domain
        driver.navigate().to(NIP_IO_EMPLOYEE2_URL);
        assertCurrentUrlStartsWith(testRealmSAMLPostLoginPage);

        // Login and check the user is successfully logged in
        testRealmSAMLPostLoginPage.form().login(bburkeUser);
        waitUntilElement(By.xpath("//body")).text().contains("principal=bburke@redhat.com");

        // Logout
        driver.navigate().to(UriBuilder.fromUri(NIP_IO_EMPLOYEE2_URL).queryParam("GLO", "true").build().toASCIIString());
        waitForPageToLoad();

        // Check logged out
        driver.navigate().to(NIP_IO_EMPLOYEE2_URL);
        assertCurrentUrlStartsWith(testRealmSAMLPostLoginPage);
    }
}
