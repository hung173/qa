package org.hung.demo.dto.response;

import lombok.Data;

@Data
public class UserListResponse {
    private String email;
    private String username;
    private String firstName;
    private String lastName;
}
