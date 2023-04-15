package com.example.securitydemo.security.config;

import com.example.securitydemo.security.common.FormAuthenticationDetailsSource;
import com.example.securitydemo.security.handler.CustomAccessDeniedHandler;
import com.example.securitydemo.security.provider.FormAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@Order(1)
@EnableWebSecurity
public class SecurityConfig {
//
////    @Autowired
////    UserDetailsService userDetailsService;
//
//    @Autowired
//    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;
//    @Autowired
//    private AuthenticationFailureHandler customAuthenticationFailureHandler;
//    @Autowired
//    private AuthenticationDetailsSource formAuthenticationDetailsSource;
//
//    @Bean
//    public AccessDeniedHandler accessDeniedHandler() {
//        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
//        accessDeniedHandler.setErrorPage("/denied");
//        return accessDeniedHandler;
//    }
//
//
//
//    @Bean
//    public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
//
//        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        authenticationManagerBuilder.authenticationProvider(formAuthenticationProvider());
//        authenticationManagerBuilder.parentAuthenticationManager(null);
//
//        http
//            .authorizeHttpRequests()
//            .requestMatchers("/", "/users", "user/login/**", "/login*")
//                .permitAll()
//            .requestMatchers("/mypage")
//                .hasRole("USER")
//            .requestMatchers("/messages")
//                .hasRole("MANAGER")
//            .requestMatchers("/config")
//                .hasRole("ADMIN")
//            .anyRequest().authenticated();
//
//        http.formLogin()
//                .loginPage("/login")
//                .loginProcessingUrl("/login_proc")
//                .authenticationDetailsSource(formAuthenticationDetailsSource)
//                .defaultSuccessUrl("/")
//                .successHandler(customAuthenticationSuccessHandler)
//                .failureHandler(customAuthenticationFailureHandler)
//                .permitAll();
//
//        http.exceptionHandling()
//            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
//            .accessDeniedPage("/denied")
//            .accessDeniedHandler(accessDeniedHandler());
//        return http.build();
//    }
//
////    @Bean
////    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
////
////        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
////
////        authenticationManager.getProviders().add(authenticationProvider());
////
////        return authenticationManager;
////
////    }
//
//    @Bean
//    public FormAuthenticationProvider formAuthenticationProvider() {
//        return new FormAuthenticationProvider();
//    }
//
////    @Bean
////    DaoAuthenticationProvider daoAuthenticationProvider() {
////        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
////        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
////        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
////        return daoAuthenticationProvider;
////    }
//
////    @Bean
////    public UserDetailsService users() {
////        String password = passwordEncoder().encode("1111");
////        UserDetails user = User.builder()
////            .username("user")
////            .password(password)
////            .roles("USER")
////            .build();
////        UserDetails manager = User.builder()
////            .username("manager")
////            .password(password)
////            .roles("MANAGER", "USER")
////            .build();
////        UserDetails admin = User.builder()
////            .username("admin")
////            .password(password)
////            .roles("ADMIN", "USER", "MANAGER")
////            .build();
////        return new InMemoryUserDetailsManager(user, manager, admin);
////    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            web.ignoring().requestMatchers("/favicon.ico", "/resources/**", "/error");
        };
    }

    private FormAuthenticationDetailsSource authenticationDetailsSource;
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;
    private AuthenticationFailureHandler customAuthenticationFailureHandler;

    @Autowired
    public SecurityConfig(FormAuthenticationDetailsSource authenticationDetailsSource, AuthenticationSuccessHandler customAuthenticationSuccessHandler, AuthenticationFailureHandler customAuthenticationFailureHandler) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
        this.customAuthenticationFailureHandler = customAuthenticationFailureHandler;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new FormAuthenticationProvider();
    }

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
//    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");

        return accessDeniedHandler;
    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }

    @Bean
    public SecurityFilterChain filterChain2(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authenticationProvider());
        authenticationManagerBuilder.parentAuthenticationManager(null);

        http
            .authorizeHttpRequests()
            .requestMatchers("/", "/users", "/user/login/**", "/error", "/login**").permitAll()
            .requestMatchers("/mypage").hasRole("USER")
            .requestMatchers("/messages").hasRole("MANAGER")
            .requestMatchers("/config").hasRole("ADMIN")
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .loginPage("/login")
            .loginProcessingUrl("/login_proc")
            .defaultSuccessUrl("/")
            .authenticationDetailsSource(authenticationDetailsSource)
            .successHandler(customAuthenticationSuccessHandler)
            .failureHandler(customAuthenticationFailureHandler)
            .permitAll()
            .and()
            .exceptionHandling()
            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            .accessDeniedPage("/denied")
            .accessDeniedHandler(accessDeniedHandler());

        http.csrf().disable();

        return http.build();
    }

}
