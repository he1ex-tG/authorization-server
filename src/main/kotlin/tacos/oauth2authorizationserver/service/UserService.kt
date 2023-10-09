package tacos.oauth2authorizationserver.service

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import tacos.oauth2authorizationserver.data.entity.User
import tacos.oauth2authorizationserver.data.repository.UserRepository
import tacos.security.UserRegistrationData
import java.nio.file.attribute.UserPrincipalNotFoundException
import kotlin.jvm.optionals.getOrElse

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) {

    fun addUser(userRegistrationData: UserRegistrationData): User {
        return userRepository.save(userRegistrationData.toUser(passwordEncoder))
    }

    fun confirmUser(userId: String): Boolean {
        val user = userRepository.findById(userId)
        user.getOrElse {
            return false
        }.apply {
            accountEnabled = true
            userRepository.save(this)
        }
        return true
    }
}