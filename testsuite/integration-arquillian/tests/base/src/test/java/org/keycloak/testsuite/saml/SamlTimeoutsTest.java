package org.keycloak.testsuite.saml;

import org.junit.Assert;
import org.junit.Test;
import org.keycloak.dom.saml.v2.SAML2Object;
import org.keycloak.dom.saml.v2.assertion.ConditionsType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationDataType;
import org.keycloak.dom.saml.v2.assertion.SubjectConfirmationType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.keycloak.testsuite.updaters.RealmAttributeUpdater;
import org.keycloak.testsuite.util.Matchers;
import org.keycloak.testsuite.util.SamlClient;
import org.keycloak.testsuite.util.SamlClientBuilder;

import java.util.List;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertThat;


/**
 * @author mhajas
 */
public class SamlTimeoutsTest extends AbstractSamlTest {

    private static final int ACCESS_CODE_LIFESPAN = 600;
    private static final int ACCESS_TOKEN_LIFESPAN = 1200;

    private SAML2Object checkSessionNotOnOrAfter(SAML2Object ob, int accessCodeLifespan, int accessTokenLifespan) {
        assertThat(ob, Matchers.isSamlResponse(JBossSAMLURIConstants.STATUS_SUCCESS));
        ResponseType resp = (ResponseType) ob;

        Assert.assertNotNull(resp);
        Assert.assertNotNull(resp.getAssertions());
        Assert.assertThat(resp.getAssertions().size(), greaterThan(0));
        Assert.assertNotNull(resp.getAssertions().get(0));
        Assert.assertNotNull(resp.getAssertions().get(0).getAssertion());

        // Conditions
        Assert.assertNotNull(resp.getAssertions().get(0).getAssertion().getConditions());
        Assert.assertNotNull(resp.getAssertions().get(0).getAssertion().getConditions());
        ConditionsType condition = resp.getAssertions().get(0).getAssertion().getConditions();

        Assert.assertEquals(XMLTimeUtil.add(condition.getNotBefore(), accessCodeLifespan * 1000L), condition.getNotOnOrAfter());

        // SubjectConfirmation (confirmationData has no NotBefore, using the previous one because it's the same)
        Assert.assertNotNull(resp.getAssertions().get(0).getAssertion().getSubject());
        Assert.assertNotNull(resp.getAssertions().get(0).getAssertion().getSubject().getConfirmation());
        List<SubjectConfirmationType> confirmations = resp.getAssertions().get(0).getAssertion().getSubject().getConfirmation();

        SubjectConfirmationDataType confirmationData = confirmations.stream()
                .map(c -> c.getSubjectConfirmationData())
                .filter(c -> c != null)
                .findFirst()
                .orElse(null);

        Assert.assertNotNull(confirmationData);
        Assert.assertEquals(XMLTimeUtil.add(condition.getNotBefore(), accessTokenLifespan * 1000L), confirmationData.getNotOnOrAfter());

        return null;
    }

    @Test
    public void testSamlResponseContainsTimeoutsAfterIdpInitiatedLogin() throws Exception {
        try(AutoCloseable c = new RealmAttributeUpdater(adminClient.realm(REALM_NAME))
                .updateWith(r -> {
                    r.setAccessCodeLifespan(ACCESS_CODE_LIFESPAN);
                    r.setAccessTokenLifespan(ACCESS_TOKEN_LIFESPAN);
                })
                .update()) {
            new SamlClientBuilder()
                    .idpInitiatedLogin(getAuthServerSamlEndpoint(REALM_NAME), "sales-post").build()
                    .login().user(bburkeUser).build()
                    .processSamlResponse(SamlClient.Binding.POST)
                    .transformObject(r -> checkSessionNotOnOrAfter(r, ACCESS_CODE_LIFESPAN, ACCESS_TOKEN_LIFESPAN))
                    .build()
                    .execute();
        }
    }

    @Test
    public void testMaxValuesForAllTimeouts() throws Exception {
        try(AutoCloseable c = new RealmAttributeUpdater(adminClient.realm(REALM_NAME))
                .updateWith(r -> {
                    r.setAccessCodeLifespan(Integer.MAX_VALUE);
                    r.setAccessTokenLifespan(Integer.MAX_VALUE);
                })
                .update()) {
            new SamlClientBuilder()
                    .idpInitiatedLogin(getAuthServerSamlEndpoint(REALM_NAME), "sales-post").build()
                    .login().user(bburkeUser).build()
                    .processSamlResponse(SamlClient.Binding.POST)
                    .transformObject(r -> checkSessionNotOnOrAfter(r, Integer.MAX_VALUE, Integer.MAX_VALUE))
                    .build()
                    .execute();
        }
    }
}
