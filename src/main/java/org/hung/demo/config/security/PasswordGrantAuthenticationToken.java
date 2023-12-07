package org.hung.demo.config.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Collection;
import java.util.Map;

public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String username;
    private final String password;

    protected PasswordGrantAuthenticationToken(String username,
                                               String password,
                                               Authentication clientPrincipal,
                                               Map<String, Object> additionalParameters
                                               ) {
        super(new AuthorizationGrantType("password"), clientPrincipal, additionalParameters);
        this.password = password;
        this.username = username;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }
}
