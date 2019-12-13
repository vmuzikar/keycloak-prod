package org.keycloak.validation;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;

import javax.ws.rs.BadRequestException;

public class ClientValidationUtil {

    public static void validate(KeycloakSession session, ClientModel client, boolean create, ErrorHandler errorHandler) throws BadRequestException {
        ClientValidationProvider provider = session.getProvider(ClientValidationProvider.class);
        if (provider != null) {
            DefaultClientValidationContext context = new DefaultClientValidationContext(create ? ClientValidationContext.Event.CREATE : ClientValidationContext.Event.UPDATE, session, client);
            provider.validate(context);

            if (!context.isValid()) {
                errorHandler.onError(context);
            }
        }
    }

    public interface ErrorHandler {

        void onError(ClientValidationContext context);

    }

}
