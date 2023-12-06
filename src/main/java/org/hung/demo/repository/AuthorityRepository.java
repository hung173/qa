package org.hung.demo.repository;

import org.hung.demo.domain.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthorityRepository extends JpaRepository<Authority, String> {

    List<Authority> findByNameIn(List<String>authorities);
}
