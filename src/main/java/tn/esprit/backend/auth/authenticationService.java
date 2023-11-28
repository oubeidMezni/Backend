package tn.esprit.backend.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tn.esprit.backend.configuration.jwtService;
import tn.esprit.backend.entities.Role;

import tn.esprit.backend.entities.User;
import tn.esprit.backend.repositories.UserRepository;

@Service
@RequiredArgsConstructor
public class authenticationService {

        private final UserRepository repository;
        private final PasswordEncoder passwordEncoder;
        private final jwtService jwtService;
        private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .Password(passwordEncoder.encode(request.getPassword()))
                .role(Role.UNIVERSITY)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return  AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword()));

var user = repository.findByEmail(request.getEmail())
        .orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        return  AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
