package tacos.oauth2authorizationserver.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }
            formLogin { }
        }
        return http.build()
    }

    @Bean
    fun usersDetailService(encoder: PasswordEncoder): UserDetailsService {
        val userAdmin = User.builder()
            .username("admin")
            .password(encoder.encode("admin"))
            .roles("ADMIN")
            .build()
        val userUser = User.builder()
            .username("user")
            .password(encoder.encode("user"))
            .roles("USER")
            .build()
        return InMemoryUserDetailsManager(userAdmin, userUser)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }
}