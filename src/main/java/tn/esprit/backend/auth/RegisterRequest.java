package tn.esprit.backend.auth;


import lombok.*;

@Data
@Builder
@AllArgsConstructor
@Setter
@Getter
public class RegisterRequest {

    private String firstName;
    private String lastName;
    private String email;
    private String Password;

}
