package tacos.authorizationserver.storage

import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class DataLoader {

    @Bean
    fun addUsers(
        usersRepository: UsersRepository,
        encoder: PasswordEncoder
    ): CommandLineRunner {
        return CommandLineRunner {
            usersRepository.save(
                Users("aaa", encoder.encode("aaa"), "ROLE_ADMIN")
            )
            usersRepository.save(
                Users("qqq", encoder.encode("qqq"), "ROLE_ADMIN")
            )
        }
    }
}