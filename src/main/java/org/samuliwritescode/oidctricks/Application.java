package org.samuliwritescode.oidctricks;

import com.vaadin.flow.component.ClientCallable;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.Anchor;
import com.vaadin.flow.component.html.Div;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.data.provider.CallbackDataProvider;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.RouteAlias;
import com.vaadin.flow.server.VaadinServletRequest;
import com.vaadin.flow.server.VaadinServletResponse;
import com.vaadin.flow.server.auth.AnonymousAllowed;
import com.vaadin.flow.spring.security.AuthenticationContext;
import com.vaadin.flow.spring.security.UidlRedirectStrategy;
import com.vaadin.flow.spring.security.VaadinWebSecurity;
import com.vaadin.flow.theme.lumo.LumoUtility;
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
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

/**
 * Example application that builds on top of https://github.com/samuliwritescode/spring-oidc-minimal and expands it by
 * adding support for:
 * 1. Back channel logout
 * 2. Refresh token handling
 * 3. Logout programmatically
 * 4. Backend calls with same access token
 */
@SpringBootApplication // <-- So that you may run this as a Spring Boot application
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args); // <-- So that you may run this directly as a Java application
    }

    @RestController
    public static class Backend {
        record DTO(String name, String description) {
        }

        @GetMapping("/rest/get")
        List<DTO> getDTOs(@RequestParam("offset") Integer offset, @RequestParam("limit") Integer limit) {
            return IntStream.range(offset, offset + limit)
                    .mapToObj(i -> new DTO("Item-%d".formatted(i), "A lot of things could potentially be said about the item number %d".formatted(i)))
                    .toList();
        }

        @GetMapping("/rest/size")
        int getSize() {
            return 10000;
        }
    }

    @Route("secured")
    @PermitAll
    public static class SecuredRoute extends Div {
        private final AuthenticationContext authenticationContext;
        private final OAuth2AuthorizedClientManager authorizedClientManager;

        private Paragraph tokenDebug;

        public SecuredRoute(@Autowired AuthenticationContext authenticationContext,
                            @Autowired OAuth2AuthorizedClientManager authorizedClientManager) {
            this.authenticationContext = authenticationContext;
            this.authorizedClientManager = authorizedClientManager;
            OAuth2AuthenticationToken auth = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            OidcUser user = (OidcUser) auth.getPrincipal();
            addClassNames(LumoUtility.Display.FLEX,
                    LumoUtility.FlexDirection.COLUMN,
                    LumoUtility.Height.FULL,
                    LumoUtility.Width.FULL,
                    LumoUtility.Background.CONTRAST_10
            );

            add(new Div() {{
                addClassNames(LumoUtility.Display.FLEX,
                        LumoUtility.FlexDirection.COLUMN,
                        LumoUtility.Border.ALL,
                        LumoUtility.BorderRadius.LARGE,
                        LumoUtility.BoxShadow.MEDIUM,
                        LumoUtility.Margin.XLARGE,
                        LumoUtility.Padding.MEDIUM,
                        LumoUtility.BoxSizing.BORDER,
                        LumoUtility.Flex.GROW,
                        LumoUtility.Background.BASE
                );

                add(new Div() {{
                    addClassNames(LumoUtility.Display.FLEX,
                            LumoUtility.FlexDirection.ROW,
                            LumoUtility.AlignItems.CENTER,
                            LumoUtility.Gap.MEDIUM);
                    add(new Paragraph("This is a secured route and you are the user '%s'".formatted(user.getName())));
                    add(new Paragraph() {{
                        tokenDebug = this;
                    }});
                    add(new Div() {{
                        addClassNames(LumoUtility.Flex.GROW);
                    }});
                    add(new Button() {{
                        addThemeVariants(ButtonVariant.LUMO_PRIMARY);
                        setText("Logout programmatically");
                        //Documented at https://vaadin.com/docs/latest/flow/security/enabling-security#security-utilities
                        addClickListener(e -> authenticationContext.logout());
                    }});
                }});

                add(new Paragraph("The grid is populated by using a external REST endpoint that shares same the access token as the browser"));

                record BackendDTO(String name, String description) {
                }
                add(new Grid<BackendDTO>() {{
                    addClassNames(LumoUtility.Flex.GROW);
                    addColumn(BackendDTO::name);
                    addColumn(BackendDTO::description);
                    var ui = UI.getCurrent();
                    setDataProvider(new CallbackDataProvider<>(
                            query -> WebClient.create()
                                    .get()
                                    .uri("http://localhost:8080/rest/get?offset=%d&limit=%d".formatted(query.getOffset(), query.getLimit()))
                                    .headers(headers -> getAccessTokenValueAndRefreshIfNecessary().ifPresent(headers::setBearerAuth))
                                    .retrieve()
                                    .bodyToFlux(BackendDTO.class)
                                    .doOnError(t -> ui.access(() -> Notification.show(t.getLocalizedMessage())))
                                    .collectList()
                                    .onErrorReturn(Collections.emptyList())
                                    .blockOptional(Duration.ofSeconds(30))
                                    .orElse(Collections.emptyList())
                                    .stream(),
                            query -> WebClient.create()
                                    .get()
                                    .uri("http://localhost:8080/rest/size")
                                    .headers(headers -> getAccessTokenValueAndRefreshIfNecessary().ifPresent(headers::setBearerAuth))
                                    .retrieve()
                                    .bodyToMono(Integer.class)
                                    .doOnError(t -> ui.access(() -> Notification.show(t.getLocalizedMessage())))
                                    .onErrorReturn(0)
                                    .blockOptional(Duration.ofSeconds(30))
                                    .orElse(0)
                    ));
                }});
            }});

            getElement().executeJs("setInterval(() => this.$server.pump(), 30000)");
        }

        @ClientCallable
        void pump() {
            getAccessTokenValueAndRefreshIfNecessary();
        }

        private Optional<String> getAccessTokenValueAndRefreshIfNecessary() {
            /*
            Invoking OAuth2AuthorizedClientManager.authorize() will return the access token and refresh token and
            more importantly it will refresh the access token if it is about to expire.

            However, nothing will invoke the method unless explicitly done so, and for that reason this is being
            called perpetually from the browser (pump() method above). This solution is a bit hacky,
            but until a better solution is invented, it will do.
             */
            try {
                OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(OAuth2AuthorizeRequest
                        .withClientRegistrationId("keycloak")
                        .principal(SecurityContextHolder.getContext().getAuthentication())
                        .attribute(HttpServletRequest.class.getName(), VaadinServletRequest.getCurrent().getHttpServletRequest())
                        .attribute(HttpServletResponse.class.getName(), VaadinServletResponse.getCurrent().getHttpServletResponse())
                        .build());

                tokenDebug.setText(
                        "Last authorized: %s, access token issued: %s, access token expires in: %s, refresh token issued: %s".formatted(
                                LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                                authorizedClient.getAccessToken().getIssuedAt().atZone(ZoneId.systemDefault()).toLocalTime().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                                ChronoUnit.SECONDS.between(Instant.now(), authorizedClient.getAccessToken().getExpiresAt()) + "s",
                                authorizedClient.getRefreshToken().getIssuedAt().atZone(ZoneId.systemDefault()).toLocalTime().format(DateTimeFormatter.ofPattern("HH:mm:ss"))
                        ));

                return Optional.of(authorizedClient.getAccessToken().getTokenValue());
            } catch (OAuth2AuthenticationException | ClientAuthorizationException e) {
                getElement().executeJs("alert('You are logged out because Keycloak decided so')");
                authenticationContext.logout();
                return Optional.empty();
            }
        }
    }

    @Route("unsecured")
    @RouteAlias("")
    @AnonymousAllowed
    public static class UnsecuredRoute extends Div {
        public UnsecuredRoute() {
            addClassNames(LumoUtility.Display.FLEX,
                    LumoUtility.AlignItems.CENTER,
                    LumoUtility.JustifyContent.CENTER,
                    LumoUtility.Height.FULL,
                    LumoUtility.Width.FULL,
                    LumoUtility.Background.CONTRAST_10
            );

            add(new Div() {{
                addClassNames(
                        LumoUtility.Background.BASE,
                        LumoUtility.Display.FLEX,
                        LumoUtility.FlexDirection.COLUMN,
                        LumoUtility.AlignItems.CENTER,
                        LumoUtility.Border.ALL,
                        LumoUtility.BorderRadius.LARGE,
                        LumoUtility.BoxShadow.MEDIUM,
                        LumoUtility.Margin.XLARGE,
                        LumoUtility.Padding.MEDIUM,
                        LumoUtility.BoxSizing.BORDER
                );
                add(new Paragraph("Welcome to unsecured route. This you may access without logging in."));
                Anchor linkToSecuredPage = new Anchor("/secured", "This route will require you to login");
                linkToSecuredPage.setRouterIgnore(true); // <-- So that spring security web filter will catch it
                add(linkToSecuredPage);
            }});
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
            //Documented at https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
            http.oauth2ResourceServer(c -> c.jwt(Customizer.withDefaults())); // <-- Resource server is needed in REST endpoint when using shared access token
            super.configure(http);
        }
    }
}
