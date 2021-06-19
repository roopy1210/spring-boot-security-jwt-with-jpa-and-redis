package com.roopy.service;

import com.roopy.dto.UserDto;
import com.roopy.entity.User;

public interface UserService {

    public User createUser(UserDto userDto);

}
