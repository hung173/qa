package org.hung.demo.config.security;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.transaction.annotation.Transactional;

public class JdbcAuthenticationService extends JdbcOAuth2AuthorizationService {

    public JdbcAuthenticationService(JdbcOperations jdbcOperations,
                                     RegisteredClientRepository registeredClientRepository) {
        super(jdbcOperations, registeredClientRepository);
    }

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        super.save(authorization);
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        super.remove(authorization);
    }

    @Override
    @Transactional
    public OAuth2Authorization findById(String id) {
        return super.findById(id);
    }

    @Override
    @Transactional
    public OAuth2Authorization findByToken(String token,
                                           OAuth2TokenType tokenType) {
        return super.findByToken(token, tokenType);
    }
}
