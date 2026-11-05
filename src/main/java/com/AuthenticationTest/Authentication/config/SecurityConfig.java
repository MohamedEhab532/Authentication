package com.AuthenticationTest.Authentication.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {



    @Bean
    public SecurityFilterChain securityFilterChain (HttpSecurity http) throws Exception {
        ApiKeyAuthFilter filter = new ApiKeyAuthFilter(
                PathPatternRequestMatcher.pathPattern("/api/**")
        );
        filter.setAuthenticationManager(authentication -> {
            String apiKey = (String) authentication.getPrincipal();
            String apiSecret = (String) authentication.getCredentials();



            if ("valid-api-key".equals(apiKey) && "valid-api-secret".equals(apiSecret)) {
                return new APIKeyAuthenticationToken(
                        List.of(new SimpleGrantedAuthority("ROLE_USER")),
                        apiKey,
                        apiSecret
                );
            } throw new BadCredentialsException("Invalid API key or secret");

        });
            http
                .csrf(csrf -> csrf.disable()).authorizeHttpRequests(
                        authorize ->authorize.requestMatchers("/api/**").authenticated().anyRequest().permitAll())
                .addFilterBefore(
                filter,
                UsernamePasswordAuthenticationFilter.class
        );
        return http.build();
    }

    }

