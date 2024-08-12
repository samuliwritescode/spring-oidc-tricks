package org.samuliwritescode.oidctricks;

import com.vaadin.flow.component.ClientCallable;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.html.Anchor;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteAlias;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinServletResponse;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import com.vaadin.flow.spring.security.AuthenticationContext;
import com.vaadin.flow.spring.security.UidlRedirectStrategy;
import com.vaadin.flow.spring.security.VaadinWebSecurity;
import jakarta.annotation.security.PermitAll;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * Example application that builds on top of https://github.com/samuliwritescode/spring-oidc-minimal and expands it by
 * adding support for:
 * 1. Back channel logout
 * 2. Refresh token handling
 * 3. Logout programmatically
 */
@SpringBootApplication // <-- So that you may run this as a Spring Boot application
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args); // <-- So that you may run this directly as a Java application
    }

    @Route("secured")
    @PermitAll
    public static class SecuredRoute extends Div {
        private final AuthenticationContext authenticationContext;
        private final OAuth2AuthorizedClientManager authorizedClientManager;

        public SecuredRoute(@Autowired AuthenticationContext authenticationContext,
                            @Autowired OAuth2AuthorizedClientManager authorizedClientManager) {
            this.authenticationContext = authenticationContext;
            this.authorizedClientManager = authorizedClientManager;
            OAuth2AuthenticationToken auth = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            OidcUser user = (OidcUser) auth.getPrincipal();

            add(new Paragraph("This is a secured route and you are the user '%s'".formatted(user.getName())));
            add(new Button() {{
                addThemeVariants(ButtonVariant.LUMO_PRIMARY);
                setText("Logout programmatically");
                //Documented at https://vaadin.com/docs/latest/flow/security/enabling-security#security-utilities
                addClickListener(e -> authenticationContext.logout());
            }});

            getElement().executeJs("setInterval(() => this.$server.pump(), 5000)");
        }

        @ClientCallable
        void pump() {
            try {
                /*
                Invoking OAuth2AuthorizedClientManager.authorize() will return the access token and refresh token and
                more importantly it will refresh the access token if it is about to expire.

                However, nothing will invoke the method unless explicitly done so, and for that reason this is being
                called perpetually from the browser. This solution is a bit hacky, but until a better solution is
                invented, it will do.
                 */
                authorizedClientManager.authorize(OAuth2AuthorizeRequest
                        .withClientRegistrationId("keycloak")
                        .principal(SecurityContextHolder.getContext().getAuthentication())
                        .attribute(HttpServletRequest.class.getName(), VaadinServletRequest.getCurrent().getHttpServletRequest())
                        .attribute(HttpServletResponse.class.getName(), VaadinServletResponse.getCurrent().getHttpServletResponse())
                        .build());
            } catch (OAuth2AuthorizationException e) {
                getElement().executeJs("alert('You are logged out because Keycloak decided so')");
                authenticationContext.logout();
            }
        }
    }

    @Route("unsecured")
    @RouteAlias("")
    @AnonymousAllowed
    public static class UnsecuredRoute extends Div {
        public UnsecuredRoute() {
            add(new Paragraph("Welcome to unsecured route. This you may access without logging in."));
            Anchor linkToSecuredPage = new Anchor("/secured", "This route will require you to login");
            linkToSecuredPage.setRouterIgnore(true); // <-- So that spring security web filter will catch it
            add(linkToSecuredPage);
        }
    }

    @EnableWebSecurity
    @Configuration
    public static class SecurityConfiguration extends VaadinWebSecurity {
        private final OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler;

        public SecurityConfiguration(@Autowired ClientRegistrationRepository clientRegistrationRepository) {
            logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            logoutSuccessHandler.setPostLogoutRedirectUri("http://localhost:8080/unsecured"); // <-- Where Keycloak will redirect after logging out
            logoutSuccessHandler.setRedirectStrategy(new UidlRedirectStrategy()); // So that Vaadin won't just default to reload the page when server responds with redirect
        }

        @Bean
        public HttpSessionEventPublisher sessionEventPublisher() {
            return new HttpSessionEventPublisher(); //<-- Necessary for the back channel logout in order to trigger the logout success handler
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.oauth2Login(Customizer.withDefaults()); // <-- This is important to let Spring Security to know to redirect to keycloak login page.
            http.logout(c -> c.logoutSuccessHandler(logoutSuccessHandler)); // <-- Logout with oauth2 must be handled with Keycloak
            //Documented at https://docs.spring.io/spring-security/reference/servlet/oauth2/login/logout.html#configure-provider-initiated-oidc-logout
            http.oidcLogout(logout -> logout.backChannel(Customizer.withDefaults())); // <-- back channel logout from Keycloak will kill the session
            super.configure(http);
        }
    }
}
