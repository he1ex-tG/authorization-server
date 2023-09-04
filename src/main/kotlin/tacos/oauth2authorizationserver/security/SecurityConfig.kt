package tacos.oauth2authorizationserver.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
//@EnableWebSecurity
class SecurityConfig {

    /*@Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            /*.authorizeHttpRequests {
                it.anyRequest().authenticated()
            }*/
            .formLogin(Customizer.withDefaults())
            .build()
    }*/

    @Bean
    fun usersDetailService(encoder: PasswordEncoder): UserDetailsService {
        val userA = User.builder()
            .username("aaa")
            .password(encoder.encode("aaa"))
            .roles("ADMIN")
            .build()
        val userB = User.builder()
            .username("qqq")
            .password(encoder.encode("qqq"))
            .roles("USER")
            .build()
        return InMemoryUserDetailsManager(userA, userB)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }
}