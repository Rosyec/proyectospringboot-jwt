package com.example.miproyectowebspringboot.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.miproyectowebspringboot.models.entity.Usuario;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    //Genera nuestra llave statica
    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager manager) {
        this.authenticationManager = manager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        String username = obtainUsername(request);
        //username = (username != null) ? username.trim() : "";

        String password = obtainPassword(request);
        //password = (password != null) ? password : "";

        if (username != null && password != null) {
            logger.info("Username desde request postman (form-data): " + username);
        }else{
            Usuario user = null;
            try {
                user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);//Asi leemos un JSON, con ObjectMapper().readValue
                username = user.getUsername();
                password = user.getPassword();
                logger.info("Username desde request postman (raw): " + username);
            } catch (IOException e) {
                e.printStackTrace();
            }

        }

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {


        String keyString = Base64.getEncoder().encodeToString(SECRET_KEY.getEncoded());
        logger.info("SECRET-KEY: " + keyString);

        //Obtenemos los roles
        Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

        //Escribimos los roles en el claims pero con tipo JSON
        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

        // Generando nuestro JWT
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(authResult.getName())
                .signWith(SECRET_KEY)
                .setExpiration(new Date(System.currentTimeMillis() + 3600000 * 4))
                .compact();

        //Declaramos el header para el response
        response.addHeader("Authorization", "Bearer " + token);// Esto es un estandar de JWT

        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        body.put("message", "Hola usuario, has iniciado sesión!");

        //Escribimos el body en el response sin antes convertirlo a JSON con ObjectMapper
        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");

    }

}
