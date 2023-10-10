package tacos.oauth2authorizationserver.integration.email

import org.springframework.integration.annotation.MessagingGateway
import org.springframework.integration.mail.MailHeaders
import org.springframework.messaging.handler.annotation.Header

@MessagingGateway(defaultRequestChannel = "emailSendChannel")
interface EmailSendInterface {

    fun sendConfirmEmail(
        @Header(MailHeaders.FROM) from: String,
        @Header(MailHeaders.TO) to: String,
        @Header(MailHeaders.SUBJECT) subject: String,
        message: String
    )
}