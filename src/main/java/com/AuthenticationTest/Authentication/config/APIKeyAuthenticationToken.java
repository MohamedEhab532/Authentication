package com.AuthenticationTest.Authentication.config;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class APIKeyAuthenticationToken extends AbstractAuthenticationToken {

    private String apiKey;
    private String apiSecret;

    public APIKeyAuthenticationToken(String apiKey, String apiSecret) {
        //super((Collection<? extends GrantedAuthority>) null);
        super(Collections.emptyList());
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        setAuthenticated(false);
    }

    public APIKeyAuthenticationToken(@Nullable Collection<? extends GrantedAuthority> authorities ,String apiKey, String apiSecret) {
        super(authorities);
        this.apiKey = apiKey;
        this.apiSecret = apiSecret;
        super.setAuthenticated(true);
        System.out.println("It works");
    }

    // Returns the API secret in the format Spring Security expects
    @Override
    public @Nullable Object getCredentials() {
        return this.apiSecret;
    }

    // Returns the API key in the format Spring Security expects
    @Override
    public @Nullable Object getPrincipal() {
        return this.apiKey;
    }
    @Override
    public void setAuthenticated (boolean isAuthenticated) throws IllegalArgumentException{
        if (isAuthenticated){
            throw  new IllegalArgumentException("Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");

        }
        super.setAuthenticated(false);
    }
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
