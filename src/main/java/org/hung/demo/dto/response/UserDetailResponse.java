package org.hung.demo.dto.response;

import lombok.Data;

import java.util.List;

@Data
public class UserDetailResponse {
    private String email;
    private String username;
    private String firstName;
    private String lastName;
//    private List<String> authorities;
}
