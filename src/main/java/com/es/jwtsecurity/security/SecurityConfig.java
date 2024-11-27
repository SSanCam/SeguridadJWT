package com.es.jwtsecurity.security;
/*
    private  SecurityFilterChain : SecurityFilterChain {
        // Filtros que vamos a poner

        authenticated
                Los endpoints LIBRES - TODOS PUEDEN ACCEDER
                Los endpoints PROTEGIDOS - SOLO PARA LOS QUE TENGAN AUTORIZACION
        JWT
            Los nuevos tokens por los que se pueden autenticar

    }
  */

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // porpia de SpringBoot
@EnableWebSecurity // SpringSecurity sabe q dentro de esta clase está la configuración de la seguridad
public class SecurityConfig {
    // metemos todos los filtros q tengan q ver con la validacion , cencriptacion de contraseña , validacion de token , etc
    /*
    (METODO)BEAN QUE ESTABLECE EL SECURITY FILTER CHAIN
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {

        return http
                .csrf(csrf -> csrf.disable()) // Deshabilitamos "Cross-Site Request Forgery" (CSRF)"
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/usuarios/login", "/usuarios/register").permitAll()
                        .anyRequest().authenticated() // Ahora mismo estamos permitiendo que cualquier petición, las permita todas
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults())
                .build();
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
