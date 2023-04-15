package com.example.securitydemo.security.config;

import com.example.securitydemo.security.common.AjaxLoginAuthenticationEntryPoint;
import com.example.securitydemo.security.filter.AjaxLoginProcessingFilter;
import com.example.securitydemo.security.handler.AjaxAccessDeniedHandler;
import com.example.securitydemo.security.handler.AjaxAuthenticationFailureHandler;
import com.example.securitydemo.security.handler.AjaxAuthenticationSuccessHandler;
import com.example.securitydemo.security.provider.AjaxAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
public class AjaxSecurityConfig {
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(ajaxAuthenticationProvider());
        return authenticationManager;
    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }

    @Bean
    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }

    @Bean
    public SecurityFilterChain FilterChain(HttpSecurity http) throws Exception {

        http
            .authorizeHttpRequests((authorize) -> authorize
                //.dispatcherTypeMatchers(DispatcherType.ASYNC).permitAll()
                .requestMatchers("/api/**").authenticated()
                .requestMatchers("/api/messages").hasRole("MANAGER")
                .requestMatchers("/api/login").permitAll()
            );


        http
            .exceptionHandling()
            .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
            .accessDeniedHandler(ajaxAccessDeniedHandler());
//            .and().addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);


        customConfigurerAjax(http);

        http.csrf().disable();
        return http.build();
    }

    private void customConfigurerAjax(HttpSecurity http) throws Exception {
        http
            .apply(new AjaxLoginConfigurer<>())
            .successHandlerAjax(ajaxAuthenticationSuccessHandler())
            .failureHandlerAjax(ajaxAuthenticationFailureHandler())
            .setAuthenticationManager(authenticationManager(authenticationConfiguration))
            .loginProcessingUrl("/api/login");
    }

//    @Bean
//    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
//        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
//        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
//        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
//        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
//        return ajaxLoginProcessingFilter;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
