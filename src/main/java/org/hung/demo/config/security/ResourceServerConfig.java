//package org.hung.demo.config.security;
//
//import org.hung.demo.common.Constants;
//import org.hung.demo.rest.filter.CookieCsrfFilter;
//import org.hung.demo.rest.filter.SpaWebFilter;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.convert.converter.Converter;
//import org.springframework.security.authentication.AbstractAuthenticationToken;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
//import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
//import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
//import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
//import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
//import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
//import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
//
//import static org.springframework.security.config.Customizer.withDefaults;
//
//@Configuration
//@EnableWebSecurity
//public class ResourceServerConfig {
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http, MvcRequestMatcher.Builder mvc) throws Exception {
//        http
//                .cors(withDefaults())
//                .csrf(csrf ->
//                        csrf
//                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                                // See https://stackoverflow.com/q/74447118/65681
//                                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
//                )
//                .addFilterAfter(new SpaWebFilter(), BasicAuthenticationFilter.class)
//                .addFilterAfter(new CookieCsrfFilter(), BasicAuthenticationFilter.class)
//                .headers(headers ->
//                        headers
////                                .contentSecurityPolicy(csp -> csp.policyDirectives(jHipsterProperties.getSecurity().getContentSecurityPolicy()))
//                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
//                                .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
//                                .permissionsPolicy(permissions ->
//                                        permissions.policy(
//                                                "camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()"
//                                        )
//                                )
//                )
//                .authorizeHttpRequests(authz ->
//                        // prettier-ignore
//                        authz
//                                .requestMatchers(mvc.pattern("/index.html"), mvc.pattern("/*.js"), mvc.pattern("/*.txt"), mvc.pattern("/*.json"), mvc.pattern("/*.map"), mvc.pattern("/*.css")).permitAll()
//                                .requestMatchers(mvc.pattern("/*.ico"), mvc.pattern("/*.png"), mvc.pattern("/*.svg"), mvc.pattern("/*.webapp")).permitAll()
//                                .requestMatchers(mvc.pattern("/app/**")).permitAll()
//                                .requestMatchers(mvc.pattern("/i18n/**")).permitAll()
//                                .requestMatchers(mvc.pattern("/content/**")).permitAll()
//                                .requestMatchers(mvc.pattern("/swagger-ui/**")).permitAll()
//                                .requestMatchers(mvc.pattern("/api/authenticate")).permitAll()
//                                .requestMatchers(mvc.pattern("/api/auth-info")).permitAll()
//                                .requestMatchers(mvc.pattern("/v3/api-docs/**")).hasAuthority(Constants.Authority.ROLE_ADMIN)
//                                .requestMatchers(mvc.pattern("/management/health")).permitAll()
//                                .requestMatchers(mvc.pattern("/management/health/**")).permitAll()
//                                .requestMatchers(mvc.pattern("/management/info")).permitAll()
//                                .requestMatchers(mvc.pattern("/management/prometheus")).permitAll()
//                                .requestMatchers(mvc.pattern("/management/**")).hasAuthority(Constants.Authority.ROLE_ADMIN)
//                                .requestMatchers(mvc.pattern("/api/users/**")).hasAuthority(Constants.Authority.ROLE_ADMIN)
//                                .requestMatchers(mvc.pattern("/api/**")).authenticated()
//                )
//                .oauth2Login(withDefaults())
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(authenticationConverter())))
//                .oauth2Client(Customizer.withDefaults());
//        return http.build();
//    }
//
//    @Bean
//    MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
//        return new MvcRequestMatcher.Builder(introspector);
//    }
//
//    Converter<Jwt, AbstractAuthenticationToken> authenticationConverter() {
//        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
//        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtGrantedAuthoritiesConverter());
//        return jwtAuthenticationConverter;
//    }
//}
