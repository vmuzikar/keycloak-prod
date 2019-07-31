/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authorization.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.authorization.attribute.Attributes;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.util.Tokens;
import org.keycloak.common.constants.ServiceAccountConstants;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.Response.Status;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakIdentity implements Identity {

    protected final AccessToken accessToken;
    protected final RealmModel realm;
    protected final KeycloakSession keycloakSession;
    protected final Attributes attributes;
    private final boolean resourceServer;
    private final String id;

    public KeycloakIdentity(KeycloakSession keycloakSession) {
        this(Tokens.getAccessToken(keycloakSession), keycloakSession);
    }

    public KeycloakIdentity(KeycloakSession keycloakSession, IDToken token) {
        this(token, keycloakSession, keycloakSession.getContext().getRealm());
    }

    public KeycloakIdentity(IDToken token, KeycloakSession keycloakSession, RealmModel realm) {
        if (token == null) {
            throw new ErrorResponseException("invalid_bearer_token", "Could not obtain bearer access_token from request.", Status.FORBIDDEN);
        }
        if (keycloakSession == null) {
            throw new ErrorResponseException("no_keycloak_session", "No keycloak session", Status.FORBIDDEN);
        }
        if (realm == null) {
            throw new ErrorResponseException("no_keycloak_session", "No realm set", Status.FORBIDDEN);
        }
        this.keycloakSession = keycloakSession;
        this.realm = realm;

        Map<String, Collection<String>> attributes = new HashMap<>();

        try {
            ObjectNode objectNode = JsonSerialization.createObjectNode(token);
            Iterator<String> iterator = objectNode.fieldNames();

            while (iterator.hasNext()) {
                String fieldName = iterator.next();
                JsonNode fieldValue = objectNode.get(fieldName);
                List<String> values = new ArrayList<>();

                if (fieldValue.isArray()) {
                    Iterator<JsonNode> valueIterator = fieldValue.iterator();

                    while (valueIterator.hasNext()) {
                        values.add(valueIterator.next().asText());
                    }
                } else {
                    String value = fieldValue.asText();

                    if (StringUtil.isNullOrEmpty(value)) {
                        continue;
                    }

                    values.add(value);
                }

                if (!values.isEmpty()) {
                    attributes.put(fieldName, values);
                }
            }

            if (token instanceof AccessToken) {
                this.accessToken = AccessToken.class.cast(token);
            } else {
                UserSessionProvider sessions = keycloakSession.sessions();
                UserSessionModel userSession = null;
                if (token.getSessionState() == null) {
                    // Create temporary (request-scoped) transient session
                    UserModel user = TokenManager.lookupUserFromStatelessToken(keycloakSession, realm, token);
                    userSession = sessions.createUserSession(KeycloakModelUtils.generateId(), realm, user, user.getUsername(), keycloakSession.getContext().getConnection().getRemoteAddr(),
                            ServiceAccountConstants.CLIENT_AUTH, false, null, null, UserSessionModel.SessionPersistenceState.TRANSIENT);
                } else {
                    userSession = sessions.getUserSession(realm, token.getSessionState());

                    if (userSession == null) {
                        userSession = sessions.getOfflineUserSession(realm, token.getSessionState());
                    }
                }

                ClientModel client = realm.getClientByClientId(token.getIssuedFor());
                AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
                ClientSessionContext clientSessionCtx;

                if (clientSession == null) {
                    RootAuthenticationSessionModel rootAuthSession = keycloakSession.authenticationSessions().getRootAuthenticationSession(realm, userSession.getId());

                    if (rootAuthSession == null) {
                        if (userSession.getUser().getServiceAccountClientLink() == null) {
                            rootAuthSession = keycloakSession.authenticationSessions().createRootAuthenticationSession(userSession.getId(), realm);
                        } else {
                            // if the user session is associated with a service account
                            rootAuthSession = new AuthenticationSessionManager(keycloakSession).createAuthenticationSession(realm, false);
                        }
                    }

                    AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

                    authSession.setAuthenticatedUser(userSession.getUser());
                    authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
                    authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(keycloakSession.getContext().getUri().getBaseUri(), realm.getName()));

                    AuthenticationManager.setClientScopesInSession(authSession);
                    clientSessionCtx = TokenManager.attachAuthenticationSession(keycloakSession, userSession, authSession);
                } else {
                    clientSessionCtx = DefaultClientSessionContext.fromClientSessionScopeParameter(clientSession, keycloakSession);
                }
                this.accessToken = new TokenManager().createClientAccessToken(keycloakSession, realm, client, userSession.getUser(), userSession, clientSessionCtx);
                if (token.getSessionState() == null) {
                    this.accessToken.setSessionState(null);
                }
            }

            AccessToken.Access realmAccess = this.accessToken.getRealmAccess();

            if (realmAccess != null) {
                attributes.put("kc.realm.roles", realmAccess.getRoles());
            }

            Map<String, AccessToken.Access> resourceAccess = this.accessToken.getResourceAccess();

            if (resourceAccess != null) {
                resourceAccess.forEach((clientId, access) -> attributes.put("kc.client." + clientId + ".roles", access.getRoles()));
            }

            ClientModel clientModel = getTargetClient();
            UserModel clientUser = null;

            if (clientModel != null) {
                clientUser = this.keycloakSession.users().getServiceAccount(clientModel);
            }

            UserModel userSession = getUserFromToken();

            this.resourceServer = clientUser != null && userSession.getId().equals(clientUser.getId());

            if (resourceServer) {
                this.id = clientModel.getId();
            } else {
                this.id = userSession.getId();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while reading attributes from security token.", e);
        }

        this.attributes = Attributes.from(attributes);
    }

    public KeycloakIdentity(AccessToken accessToken, KeycloakSession keycloakSession) {
        if (accessToken == null) {
            throw new ErrorResponseException("invalid_bearer_token", "Could not obtain bearer access_token from request.", Status.FORBIDDEN);
        }
        if (keycloakSession == null) {
            throw new ErrorResponseException("no_keycloak_session", "No keycloak session", Status.FORBIDDEN);
        }
        this.accessToken = accessToken;
        this.keycloakSession = keycloakSession;
        this.realm = keycloakSession.getContext().getRealm();

        Map<String, Collection<String>> attributes = new HashMap<>();

        try {
            ObjectNode objectNode = JsonSerialization.createObjectNode(this.accessToken);
            Iterator<String> iterator = objectNode.fieldNames();

            while (iterator.hasNext()) {
                String fieldName = iterator.next();
                JsonNode fieldValue = objectNode.get(fieldName);
                List<String> values = new ArrayList<>();

                if (fieldValue.isArray()) {
                    Iterator<JsonNode> valueIterator = fieldValue.iterator();

                    while (valueIterator.hasNext()) {
                        values.add(valueIterator.next().asText());
                    }
                } else {
                    String value = fieldValue.asText();

                    if (StringUtil.isNullOrEmpty(value)) {
                        continue;
                    }

                    values.add(value);
                }

                if (!values.isEmpty()) {
                    attributes.put(fieldName, values);
                }
            }

            AccessToken.Access realmAccess = accessToken.getRealmAccess();

            if (realmAccess != null) {
                attributes.put("kc.realm.roles", realmAccess.getRoles());
            }

            Map<String, AccessToken.Access> resourceAccess = accessToken.getResourceAccess();

            if (resourceAccess != null) {
                resourceAccess.forEach((clientId, access) -> attributes.put("kc.client." + clientId + ".roles", access.getRoles()));
            }

            ClientModel clientModel = getTargetClient();
            UserModel clientUser = null;

            if (clientModel != null) {
                clientUser = this.keycloakSession.users().getServiceAccount(clientModel);
            }

            UserModel userSession = getUserFromToken();

            this.resourceServer = clientUser != null && userSession.getId().equals(clientUser.getId());

            if (resourceServer) {
                this.id = clientModel.getId();
            } else {
                this.id = userSession.getId();
            }
        } catch (Exception e) {
            throw new RuntimeException("Error while reading attributes from security token.", e);
        }

        this.attributes = Attributes.from(attributes);
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public Attributes getAttributes() {
        return this.attributes;
    }

    public AccessToken getAccessToken() {
        return this.accessToken;
    }

    public boolean isResourceServer() {
        return this.resourceServer;
    }

    private ClientModel getTargetClient() {
        if (this.accessToken.getIssuedFor() != null) {
            return realm.getClientByClientId(accessToken.getIssuedFor());
        }

        if (this.accessToken.getAudience() != null && this.accessToken.getAudience().length > 0) {
            String audience = this.accessToken.getAudience()[0];
            return realm.getClientByClientId(audience);
        }

        return null;
    }

    private UserModel getUserFromToken() {
        if (accessToken.getSessionState() == null) {
            return TokenManager.lookupUserFromStatelessToken(keycloakSession, realm, accessToken);
        }

        UserSessionProvider sessions = keycloakSession.sessions();
        UserSessionModel userSession = sessions.getUserSession(realm, accessToken.getSessionState());

        if (userSession == null) {
            userSession = sessions.getOfflineUserSession(realm, accessToken.getSessionState());
        }

        return userSession.getUser();
    }
}
