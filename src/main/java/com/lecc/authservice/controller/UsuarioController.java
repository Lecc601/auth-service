package com.lecc.authservice.controller;

import com.lecc.authservice.dto.AuthDTO;
import com.lecc.authservice.dto.UsuarioDTO;
import com.lecc.authservice.model.Rol;
import com.lecc.authservice.model.Usuario;
import com.lecc.authservice.repository.RolRepository;
import com.lecc.authservice.repository.UsuarioRepository;
import com.lecc.authservice.service.IUsuarioService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/users")
public class UsuarioController {

    @Autowired
    UsuarioRepository usuarioRepository;
    @Autowired
    RolRepository rolRepository;
    @Autowired
    IUsuarioService usuarioService;

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> getSessionInfo() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth.getPrincipal().equals("anonymousUser"))) {
            UserDetails userDetails = (UserDetails) auth.getPrincipal();

            // Verificar si el usuario tiene rol ADMIN o CLIENTE
            boolean hasValidRole = userDetails.getAuthorities().stream()
                    .anyMatch(authority ->
                            authority.getAuthority().equals("ROLE_ADMIN") ||
                                    authority.getAuthority().equals("ROLE_USER"));

            if (!hasValidRole) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(new AuthDTO.MessageResponse("Acceso denegado: Rol no autorizado"));
            }

            Usuario usuario = usuarioRepository.findByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new RuntimeException("Error: Usuario no encontrado."));

            Set<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toSet());

            return ResponseEntity.ok(new AuthDTO.JwtResponse(
                    null, // No se envía un nuevo token
                    usuario.getId(),
                    userDetails.getUsername(),
                    usuario.getEmail(),
                    roles
            ));
        }

        return ResponseEntity.ok(new AuthDTO.MessageResponse("No hay sesión activa"));
    }
    @GetMapping("/roles")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> getAllRoles() {
        List<Rol> roles = rolRepository.findAll();
        return ResponseEntity.ok(roles);
    }

    @PutMapping("/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> assignRoleToUser(@PathVariable Long id, @RequestBody Map<String, String> request) {
        Rol.NombreRol roleName = Rol.NombreRol.valueOf(request.get("role"));

        Optional<Usuario> userOpt = usuarioRepository.findById(id);
        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Optional<Rol> rolOpt;
        try {
            rolOpt = rolRepository.findByNombre(roleName);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Rol no reconocido: " + roleName);
        }

        if (rolOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("Rol no válido");
        }

        Usuario user = userOpt.get();
        Set<Rol> nuevosRoles = new HashSet<>();
        nuevosRoles.add(rolOpt.get());
        user.setRoles(nuevosRoles);

        usuarioRepository.save(user);

        return ResponseEntity.ok("Rol asignado exitosamente");
    }
    //CRUD USUARIOS
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UsuarioDTO>> obtenerTodos() {
        List<UsuarioDTO> usuarios = usuarioService.obtenerTodos();
        return ResponseEntity.ok(usuarios);
    }


    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UsuarioDTO> obtenerPorId(@PathVariable Long id) {
        Optional<UsuarioDTO> usuario = usuarioService.obtenerPorId(id);
        return usuario.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /*@PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<Usuario> crearUsuario(@RequestBody Usuario usuario) {
        Usuario nuevoUsuario = usuarioService.crearUsuario(usuario);
        return ResponseEntity.ok(nuevoUsuario);
    }*/

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<UsuarioDTO> actualizar(@PathVariable Long id, @RequestBody UsuarioDTO usuarioDTO) {
        return ResponseEntity.ok(usuarioService.actualizarUsuario(id, usuarioDTO));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<Void> eliminar(@PathVariable Long id) {
        usuarioService.eliminarUsuario(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}/desactivar")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<Void> desactivarUsuario(@PathVariable Long id) {
        usuarioService.desactivarUsuario(id);
        return ResponseEntity.noContent().build();
    }

}