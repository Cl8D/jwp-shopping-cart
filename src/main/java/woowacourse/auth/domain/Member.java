package woowacourse.auth.domain;

import java.util.Objects;

public class Member {

    private final Email email;
    private final Password password;
    private final Nickname nickname;

    public Member(String email, String password, String nickname) {
        this.email = new Email(email);
        this.password = new Password(password);
        this.nickname = new Nickname(nickname);
    }

    public String getEmail() {
        return email.getValue();
    }

    public String getPassword() {
        return password.getValue();
    }

    public String getNickname() {
        return nickname.getValue();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Member member = (Member) o;
        return Objects.equals(email, member.email) && Objects.equals(password, member.password)
                && Objects.equals(nickname, member.nickname);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email, password, nickname);
    }
}
