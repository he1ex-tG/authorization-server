package tacos.oauth2authorizationserver.data

import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder
import tacos.oauth2authorizationserver.data.entity.User
import tacos.oauth2authorizationserver.data.repository.UserRepository

@Configuration
class Template(
    private val userRepository: UserRepository,
    private val encoder: PasswordEncoder
) {

    @Bean
    fun addUsers(): CommandLineRunner {
        return CommandLineRunner {
            val userUser = User("user", encoder.encode("user"))
            val userAdmin = User("admin", encoder.encode("admin"))
            userRepository.save(userUser)
            userRepository.save(userAdmin)
        }
    }
}