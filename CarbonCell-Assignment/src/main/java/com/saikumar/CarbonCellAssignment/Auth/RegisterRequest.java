package com.saikumar.CarbonCellAssignment.Auth;


import com.saikumar.CarbonCellAssignment.Model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String userName;
    private String userEmail;
    private String userPassword;
    private Role role;
}
