package tacos.oauth2authorizationserver.data.repository

import org.springframework.data.repository.CrudRepository
import tacos.oauth2authorizationserver.data.entity.User
import java.util.Optional

interface UserRepository : CrudRepository<User, String> {

    fun getUserByUsername(username: String): Optional<User>
}