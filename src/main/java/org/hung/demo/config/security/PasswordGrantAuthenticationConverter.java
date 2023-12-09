package org.hung.demo.config.security;

import jakarta.servlet.http.HttpServletRequest;
import org.hung.demo.domain.User;
import org.hung.demo.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Optional;
import java.util.stream.Collectors;

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    private final UserRepository userRepository;

    public PasswordGrantAuthenticationConverter(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!"password".equals(grantType)) {
            return null;
        }
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isPresent()) {
            var user = userOpt.get();
            var userAuthorities = user.getAuthorities().stream().map(authority -> new SimpleGrantedAuthority(authority.getName())).collect(
                    Collectors.toList());
            var clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
            return new PasswordGrantAuthenticationToken(username, password, clientPrincipal, null);
        }
        return null;
    }
}
