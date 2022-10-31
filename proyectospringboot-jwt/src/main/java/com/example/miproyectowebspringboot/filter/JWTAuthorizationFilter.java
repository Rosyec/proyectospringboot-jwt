package com.example.miproyectowebspringboot.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import com.example.miproyectowebspringboot.filter.JWTAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        // TODO Auto-generated constructor stub
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String header = request.getHeader("Authorization");
        if (!requiereAutenticacion(header)) {
            chain.doFilter(request, response);
            return;
        }

        Boolean tokenValido;
        Claims claims = null;

        String keyString = Base64.getEncoder().encodeToString(JWTAuthenticationFilter.SECRET_KEY.getEncoded());
        logger.info("SECRET-KEY (VALIDAR): " + keyString);

        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(JWTAuthenticationFilter.SECRET_KEY)
                    .build()
                    .parseClaimsJws(header.replace("Bearer ", "")).getBody();
            tokenValido = true;
        } catch (JwtException | IllegalArgumentException e) {
            tokenValido = false;
        }

        UsernamePasswordAuthenticationToken authenticationToken = null;
        if (tokenValido) {
            String username = claims.getSubject();
            Object roles = claims.get("authorities");

            Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
            .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
            .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));

            authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        }

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);

    }

    protected Boolean requiereAutenticacion(String header) {
        if (header == null || !header.startsWith("Bearer ")) {
            return false;
        } else {
            return true;
        }
    }

}
