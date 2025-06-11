package com.lecc.authservice.service.impl;

import com.lecc.authservice.dto.UsuarioDTO;
import com.lecc.authservice.model.Usuario;
import com.lecc.authservice.repository.UsuarioRepository;
import com.lecc.authservice.service.IUsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
public class UsuarioServiceImpl implements IUsuarioService {
    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public List<UsuarioDTO> obtenerTodos() {
        return usuarioRepository.findAll().stream()
                .map(this::convertToDTO)
                .toList();
    }

    @Override
    public Optional<UsuarioDTO> obtenerPorId(Long id) {
        return usuarioRepository.findById(id)
                .map(this::convertToDTO);
    }

    @Override
    @Transactional
    public UsuarioDTO crearUsuario(UsuarioDTO usuarioDTO) {
        Usuario usuario = convertToEntity(usuarioDTO);
        Usuario guardado = usuarioRepository.save(usuario);
        return convertToDTO(guardado);
    }

    @Override
    @Transactional
    public UsuarioDTO actualizarUsuario(Long id, UsuarioDTO usuarioDTO) {
        return usuarioRepository.findById(id).map(usuario -> {
            usuario.setNombre(usuarioDTO.getNombre());
            usuario.setApellido(usuarioDTO.getApellido());
            usuario.setUsername(usuarioDTO.getUsername());
            usuario.setEmail(usuarioDTO.getEmail());
            // Nota: no se actualiza la contraseña
            return convertToDTO(usuarioRepository.save(usuario));
        }).orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

    @Override
    @Transactional
    public void eliminarUsuario(Long id) {
        usuarioRepository.findById(id).ifPresent(usuario -> {
            if (!usuario.isActivo()) {
                usuarioRepository.deleteById(id);
            } else {
                throw new RuntimeException("El usuario está activo. Debe desactivarse antes de eliminar.");
            }
        });
    }


    @Override
    @Transactional
    public void desactivarUsuario(Long id) {
        usuarioRepository.findById(id).ifPresent(usuario -> {
            if (usuario.isActivo()) {
                usuario.setActivo(false);
                usuarioRepository.save(usuario);
            } else {
                throw new RuntimeException("El usuario ya está inactivo.");
            }
        });
    }


    private UsuarioDTO convertToDTO(Usuario usuario) {
        return UsuarioDTO.builder()
                .id(usuario.getId())
                .username(usuario.getUsername())
                .email(usuario.getEmail())
                .nombre(usuario.getNombre())
                .apellido(usuario.getApellido())
                .activo(usuario.isActivo())
                .build();
    }

    private Usuario convertToEntity(UsuarioDTO usuarioDTO) {
        return Usuario.builder()
                .id(usuarioDTO.getId())
                .username(usuarioDTO.getUsername())
                .email(usuarioDTO.getEmail())
                .nombre(usuarioDTO.getNombre())
                .apellido(usuarioDTO.getApellido())
                .activo(usuarioDTO.isActivo())
                .build();
    }

}