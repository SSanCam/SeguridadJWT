package com.es.jwtsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/ruta_protegida")
public class RutaProtegidaController {


    @GetMapping("/")
    public String rutaProtegida() {
        return "Ésto es una ruta protegida";
    }


}
