package dat3.security.for_security_tests;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/security-tests")
public class UserWithRolesController {

    UserWithRolesService userWithRolesService;

    public UserWithRolesController(UserWithRolesService userWithRolesService) {
        this.userWithRolesService = userWithRolesService;
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/{id}")
    public UserWithRolesResponse getUser(@PathVariable String id) {
        return userWithRolesService.getDemoUser(id);
    }

    @GetMapping("/current-user")
    public UserWithRolesResponse getLoggedinUser(Principal principal) {
        return userWithRolesService.getDemoUser(principal.getName());
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/admin-only")
    public String getUserV2(Principal principal) {
        return "Only by admins. User name is:  " + principal.getName();
    }

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("/user-only")
    public String getUser(Principal principal) {
        return "Only by Users. User name is: " + principal.getName();
    }
}
