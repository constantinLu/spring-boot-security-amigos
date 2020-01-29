package com.example.demo.util;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public enum AppRoles {

    USER(Sets.newHashSet()),

    ADMIN(Sets.newHashSet(AppPermissions.COURSE_READ, AppPermissions.COURSE_WRITE, AppPermissions.STUDENT_READ, AppPermissions.STUDENT_WRITE)),

    TRAINEE(Sets.newHashSet(AppPermissions.COURSE_READ, AppPermissions.STUDENT_READ));

    private final Set<AppPermissions> permissions;

    AppRoles(Set<AppPermissions> permissions) {
        this.permissions = permissions;
    }

    public Set<AppPermissions> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions  = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission())).collect(Collectors.toSet());

        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
