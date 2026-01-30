package com.amigos.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor    // this will create bean/constructor of any final field mentioned in this class
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;    // this bean will be created by spring as we used final and also @RequiredArgsConstructor is used at class level
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");   // this header in request parameter contains the jwt Bearer token (we need to extract jwt token from header)
        final String jwt;   // this will contain the jwt token
        final String userEmail;  // for our project email is our username

        // check whether jwt exists or not
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {   // if authHeader is null or it doesn't starts with "Bearer " then again call chain of filter with request and response to get jwt token
            filterChain.doFilter(request, response);    // pass the request and response to the new filter chain
            return;
        }

        // now we will try to extract jwt token from authHeader as null and non-existence of jwt token is checked above
        jwt = authHeader.substring(7);  // ignoring "Bearer " from authHeader
        userEmail = jwtService.extractUsername(jwt);    // todo extract the userEmail from JWT Token;
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) { // if user is not authenticated yet
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);    // check whether user exists in db
            if(jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        filterChain.doFilter(request,response); // pass the request and response to the new filter chain
    }
}
