package com.saikumar.CarbonCellAssignment.Auth;


import com.saikumar.CarbonCellAssignment.Config.JwtService;
import com.saikumar.CarbonCellAssignment.Model.User;
import com.saikumar.CarbonCellAssignment.Repository.UserRepository;
import com.saikumar.CarbonCellAssignment.Token.Token;
import com.saikumar.CarbonCellAssignment.Token.TokenRepository;
import com.saikumar.CarbonCellAssignment.Token.TokenType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .userName(registerRequest.getUserName())
                .userEmail(registerRequest.getUserEmail())
                .userPassword(passwordEncoder.encode(registerRequest.getUserPassword()))
                .role(registerRequest.getRole())
                .build();
        User savedUser = userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                authenticationRequest.getUserName(),
                authenticationRequest.getPassword()));
        var user = userRepository.findByUserName(
                authenticationRequest.getUserName()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user,jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getUserId());
        if(validUserTokens.isEmpty()){
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }
}
