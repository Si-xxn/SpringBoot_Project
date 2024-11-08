package com.wywin.entity;

import com.wywin.constant.Role;
import com.wywin.dto.MemberDTO;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;

@Entity
@Table(name = "member")
@Getter
@Setter
@ToString
public class Member extends BaseEntity /*implements UserDetails*/ {

    @Id
    @Column(name = "member_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email; // 이메일 ( 로그인 시 아이디로 사용 )

    @Column(nullable = false)
    private String password; // 비밀번호

    @Column(nullable = false)
    private String name; // 이름

    @Column(nullable = false)
    private String phoneNum; // 전화번호

    @Column(nullable = false)
    private String address; // 주소

    @Column(nullable = false, unique = true)
    private String nickName; // 닉네임

    @Enumerated(EnumType.STRING)
    private Role role; // 권한

    private boolean enabled=false; // 계정 활성화 여부

    public static Member createMember(MemberDTO memberDTO, PasswordEncoder passwordEncoder){
        /*Member entity를 생성하는 메소드. Member entity에 회원을 생성하는 메소드를 만들어서 관리를 한다면 코드가 변경되더라도 한 군데만 수정하면 된다.*/

        Member member = new Member();
        member.setName(memberDTO.getName());/*입력받은 이름을 db에 저장*/
        member.setEmail(memberDTO.getEmail());
        member.setAddress(memberDTO.getAddress());
        member.setPhoneNum(memberDTO.getPhoneNum());
        member.setNickName(memberDTO.getNickName());
        String password = passwordEncoder.encode(memberDTO.getPassword());
        /* 입력받은 비밀번호를 BCryptPasswordEncoder Bean을 파라미터로 넘겨서 비밀번호 암호화*/
        member.setPassword(password); /* encoding된 비밀번호를 db에 저장*/
        member.setRole(Role.USER);/* user권한 부여*/
        //member.setRole(Role.ADMIN);/* ADMIN권한 부여*/
        return member;
    }   // 회원 생성용 메서드 (dto와 암호화를 받아 Member 객체 리턴)

    public void updateMemberNickName(String nickName) {
        this.nickName = nickName;
    }
    public void updateAddress(String address) {
        this.address = address;
    }
    public void updatePhoneNum(String phoneNum) {
        this.phoneNum = phoneNum;
    }


   /*
   // UserDetails 메서드 구현
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 권한 반환
        // ex) "ROLE_USER" 또는 "ROLE_ADMIN"
        return null;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override // 계정이 만료되었는지 확인하는 메서드
              // @return 계정이 만료되지 않으면 true, 만료되었으면 false
    public boolean isAccountNonExpired() {
        return true; // 현재는 만료된 계정을 고려하지 않음
    }

    @Override // 계정이 잠겨있는지 확인하는 메서드
              // @return 계정이 잠겨있지 않으면 true, 잠겨있으면 false
    public boolean isAccountNonLocked() {
        return true; // 현재는 계정 잠금을 고려하지 않음
    }

    @Override // 자격 증명이 만료되었는지 확인하는 메서드
              // @return 자격증명이 만료되지 않았으면 true, 만료되었으면 false
    public boolean isCredentialsNonExpired() {
        return true; // 현재는 자격 증명의 만료를 고려하지 않음
    }

    @Override // 계정이 활성화 되어있는지 확인하는 메서드
              // @return 활성화되어 있으면 true, 비활성화되어 있으면 false
    public boolean isEnabled() {
        return enabled;
    }
    */
}
