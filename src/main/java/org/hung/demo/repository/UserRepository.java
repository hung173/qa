package org.hung.demo.repository;

import org.hung.demo.domain.User;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>, PagingAndSortingRepository<User,Long> {

    @EntityGraph(attributePaths = "authorities")
    Optional<User> findByUsername(String userName);

    @Modifying
    void deleteByUsername(String username);

}
