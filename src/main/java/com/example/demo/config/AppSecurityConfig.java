package com.example.demo.config;


import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtAuthenticationFilter;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.example.demo.util.AppRoles.USER;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;

    private final JwtConfig jwtConfig;

    public AppSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtAuthenticationFilter(authenticationManager(), jwtConfig))
                .addFilterAfter(new JwtTokenVerifier(jwtConfig), JwtAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .antMatchers("/students").hasRole(USER.name())
                .anyRequest()
                .authenticated();
    }


    /**
     * configure auth manage builder.
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    /**
     * setup the dao provider.
     *
     * @return provider with password encoder and my custom userService.
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }


    /**
     * in built user creation for auth.
     */
//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails admin = User.builder()
//                .username("anna")
//                .password(passwordEncoder.encode("pass123"))
//                //.roles(USER.name()) // ROLE_ADMIN
//                .authorities(USER.getGrantedAuthorities())
//                .build();
//
//        UserDetails student = User.builder()
//                .username("linda")
//                .password(passwordEncoder.encode("pass123"))
//                //.roles(ADMIN.name())
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails admintrainee = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("pass123"))
//                //.roles(TRAINEE.name())
//                .authorities(TRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(admin, student, admintrainee);
//    }


//    /**
//     * Form login
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/", "index", "/css/*", "/js/*")
//                .permitAll()
//                .antMatchers("/students").hasRole(USER.name())
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login").permitAll()
//                .defaultSuccessUrl("/courses", true) //costumize the login page
//                .and()
//                .rememberMe().tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login");

/**
 * basic Auth *
 */
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                //.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                //.and()
//                .csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/", "index", "/css/*", "/js/*")
//                .permitAll()
//                .antMatchers("/students").hasRole(USER.name())
//                //used in annotations of the controller
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), TRAINEE.name())
//                .anyRequest()
//                .authenticated()
//                .and()
//                .httpBasic();
//    }

}