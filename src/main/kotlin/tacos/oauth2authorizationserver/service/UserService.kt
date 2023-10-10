package tacos.oauth2authorizationserver.service

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import tacos.oauth2authorizationserver.data.entity.User
import tacos.oauth2authorizationserver.data.repository.UserRepository
import tacos.oauth2authorizationserver.integration.email.EmailSendInterface
import tacos.security.UserRegistrationData
import kotlin.jvm.optionals.getOrElse

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val emailSendInterface: EmailSendInterface
) {

    fun addUser(userRegistrationData: UserRegistrationData): User {
        val user = userRepository.save(userRegistrationData.toUser(passwordEncoder))
        emailSendInterface.sendConfirmEmail(
            "",
            user.email,
            "Confirm user registration",
            user.id ?: "")
        return user
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