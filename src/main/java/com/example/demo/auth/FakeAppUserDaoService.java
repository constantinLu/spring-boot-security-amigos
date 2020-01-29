package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.util.AppRoles.ADMIN;
import static com.example.demo.util.AppRoles.TRAINEE;
import static com.example.demo.util.AppRoles.USER;

@Repository("fake")
public class FakeAppUserDaoService implements ApplicationUserDao {


    PasswordEncoder passwordEncoder;

    public FakeAppUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String userName) {
        return getApplicationUsers().stream().filter(applicationUser -> userName.equals(applicationUser.getUsername())).findFirst();
    }


    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "annasmith",
                        passwordEncoder.encode("pass123"),
                        USER.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "linda",
                        passwordEncoder.encode("pass123"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "tom",
                        passwordEncoder.encode("pass123"),
                        TRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
