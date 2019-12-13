package org.keycloak.validation;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;

public class DefaultClientValidationContext implements ClientValidationContext {

    private Event event;
    private KeycloakSession session;
    private ClientModel client;

    private String error;

    public DefaultClientValidationContext(Event event, KeycloakSession session,  ClientModel client) {
        this.event = event;
        this.session = session;
        this.client = client;
    }

    public boolean isValid() {
        return error == null;
    }

    public String getError() {
        return error;
    }

    @Override
    public Event getEvent() {
        return event;
    }

    @Override
    public KeycloakSession getSession() {
        return session;
    }

    @Override
    public ClientModel getClient() {
        return client;
    }

    @Override
    public ClientValidationContext invalid(String error) {
        this.error = error;
        return this;
    }

}
