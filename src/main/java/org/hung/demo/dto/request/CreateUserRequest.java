package org.hung.demo.dto.request;

import jakarta.validation.constraints.*;
import lombok.Data;

import java.util.List;

@Data
public class CreateUserRequest {

    @NotBlank
    @Size(max = 20, message = "username length must not be greater than 20")
    @Pattern(regexp = "^[a-zA-Z0-9._-]{3,}$")
    private String username;

    private String password;

    @NotBlank
    @Email
    private String email;

    private String firstName;
    private String lastName;

    @NotEmpty
    private List<String> authorities;
}
