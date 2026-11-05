package com.AuthenticationTest.Authentication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;

public class ApiKeyAuthFilter extends AbstractAuthenticationProcessingFilter {
  private static final String API_KEY_HEADER = "API-Key";
  private static final String API_SECRET_HEADER = "API-Secret";


    public ApiKeyAuthFilter(RequestMatcher requiresAuth) {
        super(requiresAuth);
    }
    @Override
    public Authentication attemptAuthentication (HttpServletRequest request, HttpServletResponse response) throws IOException {
        System.out.println("attemptAuthentication is running!");
        String apiKey = request.getHeader(API_KEY_HEADER);
        String apiSecret = request.getHeader(API_SECRET_HEADER);

        if (apiKey == null || apiSecret == null){
            throw new RuntimeException("Missing API Key or Secret");
        }
        Authentication auth = new APIKeyAuthenticationToken(apiKey, apiSecret);
        return getAuthenticationManager().authenticate(auth);
    }

   /* @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException{

        super.successfulAuthentication(request, response, chain, authResult);
        chain.doFilter(request, response);*/


        @Override
        protected void successfulAuthentication(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain chain,
                Authentication authResult)
        throws IOException, ServletException {

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);

            chain.doFilter(request, response);
        }

    @Override
    public void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed)
            throws IOException, ServletException {

        SecurityContextHolder.clearContext();

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        response.getWriter().write(
                "{\"status\":401,\"error\":\"Unauthorized\","
                        + "\"message\":\"Invalid API key or secret\"}"
        );
    }

    }





