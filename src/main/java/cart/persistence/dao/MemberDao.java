package cart.persistence.dao;

import cart.persistence.entity.MemberEntity;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.stereotype.Repository;

@Repository
public class MemberDao {

    private final JdbcTemplate jdbcTemplate;

    public MemberDao(final JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public long insert(final MemberEntity memberEntity) {
        final String query = "INSERT INTO member(email, role, password, nickname, telephone) "
            + "VALUES (?, ?, ?, ?, ?)";
        final GeneratedKeyHolder keyHolder = new GeneratedKeyHolder();
        jdbcTemplate.update(connection -> {
            final PreparedStatement ps = connection.prepareStatement(query, new String[]{"id"});
            ps.setString(1, memberEntity.getEmail());
            ps.setString(2, memberEntity.getRole());
            ps.setString(3, memberEntity.getPassword());
            ps.setString(4, memberEntity.getNickname());
            ps.setString(5, memberEntity.getTelephone());
            return ps;
        }, keyHolder);
        return Objects.requireNonNull(keyHolder.getKey()).longValue();
    }

    public Optional<MemberEntity> findById(final Long id) {
        final String query = "SELECT m.id, m.role, m.email, m.password, m.nickname, m.telephone "
            + "FROM member m WHERE m.id = ?";
        try {
            return Optional.of(jdbcTemplate.queryForObject(query, memberRowMapper(), id));
        } catch (EmptyResultDataAccessException exception) {
            return Optional.empty();
        }
    }

    public List<MemberEntity> findAll() {
        final String query = "SELECT m.id, m.role, m.email, m.password, m.nickname, m.telephone FROM member m";
        return jdbcTemplate.query(query, memberRowMapper());
    }

    public Optional<MemberEntity> findByEmail(final String memberEmail) {
        final String query = "SELECT m.id, m.role, m.email, m.password, m.nickname, m.telephone "
            + "FROM member m WHERE m.email = ?";
        try {
            return Optional.ofNullable(
                jdbcTemplate.queryForObject(query, memberRowMapper(), memberEmail));
        } catch (EmptyResultDataAccessException exception) {
            return Optional.empty();
        }
    }

    private RowMapper<MemberEntity> memberRowMapper() {
        return (result, count) ->
            new MemberEntity(result.getLong("id"), result.getString("role"),
                result.getString("email"), result.getString("password"),
                result.getString("nickname"), result.getString("telephone"));
    }
}
