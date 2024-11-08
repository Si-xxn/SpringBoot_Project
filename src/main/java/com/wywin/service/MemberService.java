package com.wywin.service;

import com.wywin.dto.MemberUpdateDTO;
import com.wywin.entity.Member;
import com.wywin.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Log4j2
public class MemberService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    public Member saveMember(Member member){    // 회원 가입시 이메일 검증 후 회원 저장
        validateDuplicateMember(member); // 28행 메서드 실행
        return memberRepository.save(member);
    }

    private void validateDuplicateMember(Member member) {
        /*이미 가입된 회원의 경우 IllegalStateException 예외 발생 시킴*/
        Member findMember = memberRepository.findByEmail(member.getEmail());
        if(findMember != null){
            throw new IllegalStateException("이미 가입된 회원입니다.");
            //IllegalStateException -> 사용자가 값을 제대로 입력했지만, 개발자 코드가 값을 처리할 준비가 안된 경우에 발생한다.
        }
    }

    @Override // 이메일 정보를 받아 처리 함
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        /*UsernameNotFoundException 인터페이스의 loadUserByUsername() 메소드를 오버라이딩함. 로그인할 유저의 email을 파라미터로 전달 받음*/
        Member member = memberRepository.findByEmail(email);
        // 이메일을 받아 찾아오고 Member 객체로 담음

        if(member == null){  // member에 값이 비어 있으면 없는 회원으로 예외 발생
            throw new UsernameNotFoundException(email);
        }


        // 객체가 있으면 User 객체에 빌더 패턴으로 값을 담아 리턴한다.
        return User.builder()/*UserDetail을 구현하고 있는 User 객체를 반환해줌.
        User 객체를 생성하기 위해서 생성자로 회원의 이메일, 비밀번호, role을 파라미터로 넘겨 줌*/
                .username(member.getEmail())
                .password(member.getPassword())
                .roles(member.getRole().toString())
                .build();
    }

    public Long updateMember(MemberUpdateDTO memberUpdateDTO) { // 회원 정보 수정 닉네임, 전화번호, 주소 수정
        Member member = memberRepository.findByEmail(memberUpdateDTO.getEmail());
        member.updateMemberNickName(memberUpdateDTO.getNickName());
        member.updatePhoneNum(memberUpdateDTO.getPhoneNum());
        member.updateAddress(memberUpdateDTO.getAddress());

        memberRepository.save(member);
        log.info(member);

        return member.getId();
    }

    /* 이메일로 사용자 조회 후 현재 비밀번호 확인 메서드
    * @param email 사용자 이메일
    * @param currentPassword 현재 비밀번호
    * @return 비밀번호가 맞으면 true, 틀리면 false
    */
    public int verifyCurrentPassword(String email, String currentPassword) {
        Member member = memberRepository.findByEmail(email);

        // 사용자가 존재하고 비밀버호가 일치할 경우 1 반환
        if(member == null && !passwordEncoder.matches(currentPassword, member.getPassword())) {
            return 0;
        } else {
            return 1;
        }
    }

    /* 사용자 비밀번호 변경 메서드
    * @param email 사용자 이메일
    * @param newPassword 변경할 새 비밀번호
    * @return 비밀번호 변경 성공 여부
    */
    public int changePassword(String email, String newPassword) {
        Member member = memberRepository.findByEmail(email);

        // 사용자가 존재할 경우 비밀번호 변경
        if(member != null) {
            String encodedPassword = passwordEncoder.encode(newPassword); // 새 비밀번호 암호화
            member.setPassword(encodedPassword); // 사용자 객체에 암호화된 비밀번호 설정
            return 1; // 성공시 1 반환
        }
        return 0; // 사용자가 존재하지 않으면 0 반환
    }


}
