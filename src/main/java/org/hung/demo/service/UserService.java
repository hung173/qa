package org.hung.demo.service;

import lombok.extern.slf4j.Slf4j;
import org.hung.demo.dto.request.CreateUserRequest;
import org.hung.demo.dto.response.UserDetailResponse;
import org.hung.demo.dto.response.UserListResponse;
import org.hung.demo.exceptions.BadRequestException;
import org.hung.demo.exceptions.ErrorCode;
import org.hung.demo.exceptions.ResourceNotFoundException;
import org.hung.demo.mapper.UserMapper;
import org.hung.demo.repository.AuthorityRepository;
import org.hung.demo.repository.UserRepository;
import org.hung.demo.rest.common.StandardResponse;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;

    private final UserMapper userMapper;

    private final AuthorityRepository authorityRepository;

    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository
            , UserMapper userMapper,
                       AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.authorityRepository = authorityRepository;
        this.passwordEncoder = new BCryptPasswordEncoder(12);
    }

    public StandardResponse<List<UserListResponse>> getUserList(Pageable pageRequest) {
        var userPage = userRepository.findAll(pageRequest);
        return StandardResponse.successPaging(
                userPage.getContent().stream().map(user -> userMapper.userToUserListResponse(
                        user)).collect(Collectors.toList()),
                userPage);
    }

    public UserDetailResponse getUserDetail(String username) {
        return userRepository.findByUsername(username).map(user -> userMapper.userToUserDetail(user))
                .orElseThrow(() -> new ResourceNotFoundException(ErrorCode.USER_NOT_FOUND));
    }

    public UserDetailResponse createUser (CreateUserRequest createUserRequest) {
        var authorities = authorityRepository.findByNameIn(createUserRequest.getAuthorities());
        if (authorities.size() != createUserRequest.getAuthorities().size()) {
            throw new BadRequestException("invalid authority");
        }
        var user = userMapper.createUserRequestToUser(createUserRequest);
        user.setAuthorities(authorities);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user = userRepository.save(user);
        return UserMapper.INSTANCE.userToUserDetail(user);
    }

    public void deleteUser(String username) {
        userRepository.deleteByUsername(username);
    }
}
