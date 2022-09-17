package com.example.login.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class WebSecurityConfiguration {

  private final ClientRegistrationRepository clientRegistrationRepository;

  public WebSecurityConfiguration(ClientRegistrationRepository clientRegistrationRepository) {
    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests(registry -> {
      registry.mvcMatchers("/actuator/health").permitAll();
      registry.anyRequest().authenticated();
    });
    http.oauth2Client();
    http.oauth2Login();
    http.logout(logout -> {
      logout.logoutSuccessHandler(oidcLogoutSuccessHandler());
    });
    return http.build();
  }

  private LogoutSuccessHandler oidcLogoutSuccessHandler() {
    OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

    // Sets the location that the End-User's User Agent will be redirected to
    // after the logout has been performed at the Provider
    logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

    return logoutSuccessHandler;
  }
}
