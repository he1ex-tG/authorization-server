package tacos.oauth2authorizationserver.service

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import tacos.oauth2authorizationserver.data.entity.User
import tacos.oauth2authorizationserver.data.repository.UserRepository
import tacos.security.UserRegistrationData

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) {

    fun addUser(userRegistrationData: UserRegistrationData): User {
        return userRepository.save(userRegistrationData.toUser(passwordEncoder))
    }
}