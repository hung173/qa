package org.hung.demo.rest;

import jakarta.validation.Valid;
import org.hung.demo.config.security.SecurityUtils;
import org.hung.demo.dto.request.CreateUserRequest;
import org.hung.demo.dto.response.UserDetailResponse;
import org.hung.demo.dto.response.UserListResponse;
import org.hung.demo.dto.response.UserReportResponse;
import org.hung.demo.rest.common.StandardResponse;
import org.hung.demo.service.UserService;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }


    @GetMapping("")
    public StandardResponse<List<UserListResponse>> getUserList(Pageable pageRequest) {
        var user = SecurityUtils.getCurrentUserLogin();
        return userService.getUserList(pageRequest);
    }

    @GetMapping("/{username}")
    public StandardResponse<UserDetailResponse> getUserDetail(@PathVariable(name = "username") String username) {
        return StandardResponse.success(userService.getUserDetail(username));
    }

    @PostMapping("")
    public StandardResponse<UserDetailResponse> createUser(@RequestBody @Valid
                                               CreateUserRequest createUserRequest) {
        return StandardResponse.success(userService.createUser(createUserRequest));
    }

    @DeleteMapping("/{username}")
    public StandardResponse<String> deleteUser(@PathVariable  String username) {
        userService.deleteUser(username);
        return StandardResponse.success("SUCCESS");
    }

    @GetMapping("/report")
    public StandardResponse<List<UserReportResponse>> reportUser() {
        return StandardResponse.success(userService.reportUser());
    }
}
