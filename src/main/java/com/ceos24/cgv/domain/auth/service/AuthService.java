package com.ceos24.cgv.domain.auth.service;

import com.ceos24.cgv.domain.auth.dto.request.LoginRequest;
import com.ceos24.cgv.domain.auth.dto.request.SignUpRequest;
import com.ceos24.cgv.domain.member.Role;
import com.ceos24.cgv.domain.member.entity.Member;
import com.ceos24.cgv.domain.member.repository.MemberRepository;
import com.ceos24.cgv.global.exception.BusinessException;
import com.ceos24.cgv.global.exception.ErrorCode;
import com.ceos24.cgv.global.security.CustomUserDetails;
import com.ceos24.cgv.global.security.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final String adminToken;
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final AuthenticationManager authenticationManager;

    public AuthService(
            @Value("${admin.token}") String adminToken,
            MemberRepository memberRepository,
            PasswordEncoder passwordEncoder,
            JwtProvider jwtProvider,
            AuthenticationManager authenticationManager) {
        this.adminToken = adminToken;
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.authenticationManager = authenticationManager;
    }

    @Transactional
    public void signUp(SignUpRequest request) {

        if (memberRepository.existsByLoginId(request.loginId())) {
            throw new BusinessException(ErrorCode.AUTH_LOGIN_ID_ALREADY_EXISTS);
        }

        if (memberRepository.existsByEmail(request.email())) {
            throw new BusinessException(ErrorCode.AUTH_EMAIL_ALREADY_EXISTS);
        }

        Role role;

        if (adminToken.equals(request.adminToken())) {
            role = Role.ADMIN;
        } else {
            role = Role.USER;
        }

        Member member = Member.builder()
                .loginId(request.loginId())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .name(request.name())
                .role(role)
                .build();

        memberRepository.save(member);
    }

    public String login(LoginRequest request) {

        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(request.loginId(), request.password());

            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            return jwtProvider.createAccessToken(userDetails.getMemberId().toString());
        } catch (AuthenticationException e) {
            throw new BusinessException(ErrorCode.AUTH_INVALID_CREDENTIALS);
        }
    }
}
