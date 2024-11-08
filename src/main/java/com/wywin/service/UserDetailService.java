package com.wywin.service;

import com.wywin.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
// 스프링 시큐리티에서 사용자 정보를 가져오는 인터페이스
public class UserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override // 사용자 이름을 email로 사용자의 정보를 가져옴
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return (UserDetails) memberRepository.findByEmail(email);
    }
}
