package dat3.security.for_security_tests;


import dat3.security.dto.UserWithRolesRequest;
import dat3.security.entity.Role;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import dat3.security.entity.UserWithRoles;
import dat3.security.repository.UserWithRolesRepository;


@Service
public class UserWithRolesService {

  private  final UserWithRolesRepository userWithRolesRepository;


  public UserWithRolesService(UserWithRolesRepository userWithRolesRepository) {
    this.userWithRolesRepository = userWithRolesRepository;
  }

  public UserWithRolesResponse addDemoUser(UserWithRolesRequest body){
    if(userWithRolesRepository.existsById(body.getUsername())){
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"This user name is taken");
    }
    if(userWithRolesRepository.existsByEmail(body.getEmail())){
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"This email is used by another user");
    }
    UserWithRoles userWithRoles = new UserWithRoles(body);
    userWithRoles.addRole(Role.USER);
    return new UserWithRolesResponse(userWithRolesRepository.save(userWithRoles));
  }

  public UserWithRolesResponse getDemoUser(String id){
    UserWithRoles user = userWithRolesRepository.findById(id).orElseThrow(()-> new ResponseStatusException(HttpStatus.NOT_FOUND,"User not found"));
    return new UserWithRolesResponse(user);
  }

  public UserWithRoles getCompleteDemoUser(String id) {
    return userWithRolesRepository.findById(id).orElseThrow(()-> new ResponseStatusException(HttpStatus.NOT_FOUND,"User not found"));
  }

}
