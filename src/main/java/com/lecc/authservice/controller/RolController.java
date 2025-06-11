package com.lecc.authservice.controller;

import com.lecc.authservice.model.Rol;
import com.lecc.authservice.repository.RolRepository;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@SecurityRequirement(name = "bearerAuth")
@RestController
@RequestMapping("/api/roles")
public class RolController {

    @Autowired
    RolRepository rolRepository;

    // Obtener todos los roles
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<Rol>> getAllRoles() {
        return ResponseEntity.ok(rolRepository.findAll());
    }
    // Crear nuevo rol
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> createRole(@RequestBody Rol rol) {
        if (rolRepository.existsByNombre(rol.getNombre())) {
            return ResponseEntity.badRequest().body("El rol ya existe");
        }
        return ResponseEntity.ok(rolRepository.save(rol));
    }

    // Obtener rol por ID
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getRoleById(@PathVariable Long id) {
        return rolRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // Actualizar un rol
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> updateRole(@PathVariable Long id, @RequestBody Rol rolDetails) {
        return rolRepository.findById(id).map(rol -> {
            rol.setNombre(rolDetails.getNombre());
            return ResponseEntity.ok(rolRepository.save(rol));
        }).orElse(ResponseEntity.notFound().build());
    }

    // Eliminar un rol
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<?> deleteRole(@PathVariable Long id) {
        return rolRepository.findById(id).map(rol -> {
            rolRepository.delete(rol);
            return ResponseEntity.ok("Rol eliminado correctamente");
        }).orElse(ResponseEntity.notFound().build());
    }
}