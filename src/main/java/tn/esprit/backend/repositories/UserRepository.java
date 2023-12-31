package tn.esprit.backend.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import tn.esprit.backend.entities.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

    Optional<User> findByEmail(String email);
}
