package tacos.oauth2authorizationserver

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class Oauth2AuthorizationServerApplication

fun main(args: Array<String>) {
	runApplication<Oauth2AuthorizationServerApplication>(*args)
}
