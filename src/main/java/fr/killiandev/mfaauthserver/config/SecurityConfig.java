package fr.killiandev.mfaauthserver.config;

import fr.killiandev.mfaauthserver.auth.handler.ChainedAuthenticationHandler;
import fr.killiandev.mfaauthserver.auth.handler.ChainedAuthenticationProcess;
import fr.killiandev.mfaauthserver.auth.process.AntiExploitAuthenticationProcessFilter;
import fr.killiandev.mfaauthserver.auth.process.mfa.MFAAuthenticationFilter;
import fr.killiandev.mfaauthserver.auth.process.mfa.MFAAuthenticationProcess;
import fr.killiandev.mfaauthserver.auth.process.question.QuestionAuthenticationFilter;
import fr.killiandev.mfaauthserver.auth.process.question.QuestionAuthenticationProcess;
import fr.killiandev.mfaauthserver.handler.CustomDeniedHandlerHandler;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
        ;

        http

                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML))
                        .accessDeniedHandler(new CustomDeniedHandlerHandler()))
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        // define the chained authentication process and create the handler to manage it
        List<ChainedAuthenticationProcess> processes =
                List.of(new MFAAuthenticationProcess(), new QuestionAuthenticationProcess());
        ChainedAuthenticationHandler chainedAuthenticationHandler = new ChainedAuthenticationHandler(processes);

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/mfa", "/question")
                        .hasRole("NO_COMPLETE_AUTH") // all the route of the chained process
                        .anyRequest()
                        .authenticated())

                // configuration to enable the chained core authentication process
                .formLogin(config -> config.successHandler(chainedAuthenticationHandler))
                .addFilterBefore(
                        new AntiExploitAuthenticationProcessFilter(processes),
                        UsernamePasswordAuthenticationFilter.class)

                // All process filter here
                .addFilterAfter(
                        new MFAAuthenticationFilter(authenticationManager, chainedAuthenticationHandler),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(
                        new QuestionAuthenticationFilter(authenticationManager, chainedAuthenticationHandler),
                        MFAAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://oauth.pstmn.io/v1/callback")
                .scopes(config -> config.addAll(List.of(OidcScopes.OPENID, OidcScopes.PROFILE)))
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build())
                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(client);
    }
}
