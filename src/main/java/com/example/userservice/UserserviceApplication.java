package com.example.userservice;

import com.example.userservice.domain.Role;
import com.example.userservice.domain.User;
import com.example.userservice.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserserviceApplication.class, args);
    }

    // encoding 에 필요한 encoder 를 빈 생성
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null,"aaa","aaa1","aaa2",new ArrayList<>()));
            userService.saveUser(new User(null,"bbb","bbb1","bbb2",new ArrayList<>()));
            userService.saveUser(new User(null,"ccc","ccc1","ccc2",new ArrayList<>()));
            userService.saveUser(new User(null,"ddd","ddd1","ddd2",new ArrayList<>()));

            userService.addRoleToUser("aaa1","ROLE_USER");
            userService.addRoleToUser("bbb1","ROLE_USER");
            userService.addRoleToUser("bbb1","ROLE_MANAGER");
            userService.addRoleToUser("ccc1","ROLE_USER");
            userService.addRoleToUser("ccc1","ROLE_MANAGER");
            userService.addRoleToUser("ccc1","ROLE_ADMIN");
            userService.addRoleToUser("ddd1","ROLE_USER");
            userService.addRoleToUser("ddd1","ROLE_MANAGER");
            userService.addRoleToUser("ddd1","ROLE_ADMIN");
            userService.addRoleToUser("ddd1","ROLE_SUPER_ADMIN");

        };
    }
}
