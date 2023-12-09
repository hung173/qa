package org.hung.demo.websocket;

import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;

@Controller
@Slf4j
public class WebSocketController {


    /**
     * <p>{@link MessageMapping @MessageMapping} : topic để return về client
     * <p>{@link SendTo @SendTo} : topic để nhận message từ client
     */
    @MessageMapping("/hello")
    @SendTo("/topic/greetings")
    public String helloFromClient(String message) {
        log.info("get message from client : {}", message);
        return "hello";
    }
}
