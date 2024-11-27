package com.es.jwtsecurity.service;

import com.es.jwtsecurity.dto.UsuarioRegisterDTO;
import com.es.jwtsecurity.model.Usuario;
import com.es.jwtsecurity.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service // Es "nuestro" UsuarioService
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;



    /**
     * @param username
     * @return Devuelve un usuario buscado por su nombre
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // BUSCO EL USUARIO POR EL NOMBRE EN LA BBDD
        Usuario usuario = usuarioRepository
                .findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));


        // RETORNAMOS UN USERDETAILS - que es un usuario,
        UserDetails userDetails = User
                .builder()
                .username(usuario.getUsername())
                .password(usuario.getPassword())
                .roles(usuario.getRoles().split(", "))
                .build();

        return userDetails;
    }


    public UsuarioRegisterDTO registerUser(UsuarioRegisterDTO user) {
        if (usuarioRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("El nombre de usuario ya existe");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword())); // hashear lacontraseña
        user.setRoles(("ROLE_USER"));
        usuarioRepository.save(
                new Usuario(null, user.getUsername(), user.getPassword(), user.getRoles())
        );
        return user;
    }


}
