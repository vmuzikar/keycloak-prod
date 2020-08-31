<%@page import="org.keycloak.AuthorizationContext" %>
<%@ page import="org.keycloak.KeycloakSecurityContext" %>

<%
    KeycloakSecurityContext keycloakSecurityContext = (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    AuthorizationContext authzContext = keycloakSecurityContext.getAuthorizationContext();
%>

<html>
<body>
<h2>Granted</h2>
<%@include file="../logout-include.jsp"%>

<ul>
    <%
        if (authzContext.hasPermission("Resource A", "read")) {
    %>
    <li>
        Do read stuff
    </li>
    <%
        }
    %>

    <%
        if (authzContext.hasPermission("Resource A", "write")) {
    %>
    <li>
        Do write stuff
    </li>
    <%
        }
    %>
</ul>
</body>
</html>