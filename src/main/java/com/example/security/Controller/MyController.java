package com.example.security.Controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;

@RestController
public class MyController {
    @GetMapping("/current-user")
    public ResponseEntity<?> getCurrentUser() {
        return ResponseEntity.ok(SecurityContextHolder.getContext().getAuthentication());
    }
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/blog")
    public ResponseEntity<?> blog() {
        return ResponseEntity.ok("Blog");
    }
    @RolesAllowed("ADMIN")
    @GetMapping("/shop")
    public ResponseEntity<?> shop() {
        return ResponseEntity.ok("Shop");
    }
}
