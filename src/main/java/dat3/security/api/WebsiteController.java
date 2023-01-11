package dat3.security.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class WebsiteController {

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String getIndex() {
        return "index.html";
    }
}
