package com.example.miproyectowebspringboot.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.miproyectowebspringboot.models.entity.Usuario;
import com.example.miproyectowebspringboot.service.JWTService;
import com.fasterxml.jackson.databind.ObjectMapper;


public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Autowired
    private JWTService jwtService;

    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager manager, JWTService jwtService) {
        this.authenticationManager = manager;
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
        this.jwtService = jwtService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        String username = obtainUsername(request);
        // username = (username != null) ? username.trim() : "";

        String password = obtainPassword(request);
        // password = (password != null) ? password : "";

        if (username != null && password != null) {
            logger.info("Username desde request postman (form-data): " + username);
        } else {
            Usuario user = null;
            try {
                user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);// Asi leemos un JSON, con
                                                                                             // ObjectMapper().readValue
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
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {

        String token = jwtService.crearAutenticacion(authResult);
        response.addHeader("Authorization", "Bearer " + token);

        Map<String, Object> body = new HashMap<>();
        body.put("token", token);
        body.put("user", (User) authResult.getPrincipal());
        body.put("message", "Hola usuario, has iniciado sesión!");


        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        // Cuando la autenticacion es incorrecta
        Map<String, Object> body = new HashMap<>();
        body.put("message", "onError: Alguno de los parametros son invalidos");
        body.put("error", failed.getMessage());

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setContentType("application/json");
        response.setStatus(401);

    }

}
