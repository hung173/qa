package org.hung.demo.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CreateUserRequest {

    @NotBlank
    @Size(max = 20, message = "username length must not be greater than 20")
    @Pattern(regexp = "^[a-zA-Z0-9._-]{3,}$")
    private String username;

    @NotBlank
    @Email
    private String email;
    private String firstName;
    private String lastName;
}
