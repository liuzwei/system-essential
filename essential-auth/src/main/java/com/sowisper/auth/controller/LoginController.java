package com.sowisper.auth.controller;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.sowisper.auth.pojo.params.LoginParams;
import com.sowisper.auth.service.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author liuzhaowei
 * @date 2023-06-14
 */
@RequestMapping("/login")
@RestController
public class LoginController {

    private final UserService userService;

    public LoginController(UserService userService) {
        this.userService = userService;
    }

    /**
     * 登录
     * @param params 登录信息
     * @return token
     */
    @PostMapping("")
    public String login(@RequestBody LoginParams params) {
        GsonBuilder gsonBuilder = new GsonBuilder();
        Gson gson = gsonBuilder.create();

        return gson.toJson(userService.login(params.getUsername(), params.getPassword()));
    }

}
