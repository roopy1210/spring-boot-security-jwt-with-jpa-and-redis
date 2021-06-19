package com.roopy.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class HelloController {

    @PostMapping("/admin")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<Map<String,String>> admin() throws Exception {

        Map<String,String> retObj = new HashMap<>();
        retObj.put("msg","Admin Page!!!!");

        return new ResponseEntity<>(retObj, HttpStatus.OK);
    }

    @PostMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<Map<String,String>> user() throws Exception {

        Map<String,String> retObj = new HashMap<>();
        retObj.put("msg","User Page!!!");

        return new ResponseEntity<>(retObj, HttpStatus.OK);
    }

}
