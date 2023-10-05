package tacos.oauth2authorizationserver.web

import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.servlet.mvc.support.RedirectAttributes
import tacos.oauth2authorizationserver.service.UserService
import tacos.security.UserRegistrationData

@Controller
class WebAuthorization(
    private val userService: UserService
) {

    @GetMapping("/login")
    fun getLogin(): String {
        return "login"
    }

    @GetMapping("/registration")
    fun registration(): String {
        return "registration"
    }

    @PostMapping("/registration")
    fun newUser(
        userRegistrationData: UserRegistrationData,
        redirectAttributes: RedirectAttributes
    ): String {
        userService.addUser(userRegistrationData)
        redirectAttributes.addFlashAttribute("newUsername", userRegistrationData.username)
        return "redirect:/login"
    }
}