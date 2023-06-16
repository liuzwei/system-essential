package com.sowisper.auth.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/user")
@RestController
public class UserController {

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/{id}")
    public String userDetail(@PathVariable String id){
        return "UserDetail " + id;
    }

    @PreAuthorize("hasRole('ROLE_ROOT')")
    @GetMapping("/all")
    public String allUsers(){

        return "AllUsers";
    }

}
