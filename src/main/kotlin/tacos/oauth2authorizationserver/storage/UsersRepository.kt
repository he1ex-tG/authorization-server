package tacos.oauth2authorizationserver.storage

import org.springframework.data.repository.CrudRepository
import java.util.Optional

interface UsersRepository : CrudRepository<Users, Long> {

    fun findByUsername(username: String): Optional<Users>
}