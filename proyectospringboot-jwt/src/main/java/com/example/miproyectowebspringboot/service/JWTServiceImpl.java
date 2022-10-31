package com.example.miproyectowebspringboot.service;

import java.io.IOException;
import java.security.Key;
import java.sql.Date;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.example.miproyectowebspringboot.filter.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTServiceImpl implements JWTService{

    // Genera nuestra llave statica
    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    @Override
    public String crearAutenticacion(Authentication authentication) throws JsonProcessingException {
       
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();

        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(authentication.getName())
                .signWith(SECRET_KEY)
                .setExpiration(new Date(System.currentTimeMillis() + 3600000 * 4))
                .compact();

        return token;
    }

    @Override
    public Boolean validarToken(String token) {

        String keyString = Base64.getEncoder().encodeToString(SECRET_KEY.getEncoded());
        System.out.println("SECRET-KEY (VALIDAR): " + keyString);

        try {
            obtenerClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }

    }

    @Override
    public Claims obtenerClaims(String token) {
        Claims claims = Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(resolver(token)).getBody();
        return claims;
    }

    @Override
    public String obtenerUsername(String token) {

        return obtenerClaims(token).getSubject();
    }

    @Override
    public Collection<? extends GrantedAuthority> obtenerRoles(String token) throws IOException{
        Object roles = obtenerClaims(token).get("authorities");
        Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
            .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
            .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
        return authorities;
    }

    @Override
    public String resolver(String token) {
        if (token != null && token.startsWith("Barer ")) {
            return token.replace("Bearer ", "");
        } else{
            return null;
        }
    }
    
}
