package com.roopy.repository;

import com.roopy.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * 사용자정보 조회 및 권한목록 조회
     *
     * @param username - 사용자 ID
     * @return 사용자 ID에 해당하는 사용자 정보
     */
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
