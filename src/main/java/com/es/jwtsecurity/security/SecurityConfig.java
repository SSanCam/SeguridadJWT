package com.es.jwtsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // porpia de SpringBoot
@EnableWebSecurity // SpringSecurity sabe q dentro de esta clase está la configuración de la seguridad
public class SecurityConfig {
// metemos todos los filtros q tengan q ver con la validacion , cencriptacion de contraseña , validacion de token , etc

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

}
