package com.fitnessdiary.repository.user;

import com.fitnessdiary.entity.user.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role,Integer> {
}
