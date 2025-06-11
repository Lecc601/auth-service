package com.lecc.authservice.service;

import com.lecc.authservice.dto.UsuarioDTO;
import com.lecc.authservice.model.Usuario;

import java.util.List;
import java.util.Optional;

public interface IUsuarioService {
    List<UsuarioDTO> obtenerTodos();
    Optional<UsuarioDTO> obtenerPorId(Long id);
    UsuarioDTO crearUsuario(UsuarioDTO usuarioDTO);
    UsuarioDTO actualizarUsuario(Long id, UsuarioDTO usuarioDTO);
    void eliminarUsuario(Long id);
    void desactivarUsuario(Long id);
}