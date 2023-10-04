package tacos.oauth2authorizationserver.data.repository

import org.springframework.data.repository.CrudRepository
import tacos.oauth2authorizationserver.data.entity.User

interface UserRepository : CrudRepository<User, String>