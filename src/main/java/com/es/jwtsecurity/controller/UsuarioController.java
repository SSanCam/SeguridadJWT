package com.es.jwtsecurity.controller;

import com.es.jwtsecurity.dto.UsuarioLoginDTO;
import com.es.jwtsecurity.dto.UsuarioRegisterDTO;
import com.es.jwtsecurity.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @PostMapping("/login")
    public String login(@RequestBody UsuarioLoginDTO usuarioLoginDTO) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(usuarioLoginDTO.getUsername(), usuarioLoginDTO.getPassword())
        );
        return authentication.toString();
    }


    @PostMapping("/register")
    public ResponseEntity<UsuarioRegisterDTO> register(@RequestBody UsuarioRegisterDTO usuarioRegisterDTO) {
        //System.out.print();
        customUserDetailsService.registerUser(usuarioRegisterDTO);
        return new ResponseEntity<UsuarioRegisterDTO>(usuarioRegisterDTO, HttpStatus.OK);
    }


}
