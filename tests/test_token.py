"""CSRF token 安全回归测试。

全部 15 个测试都直接调用 :mod:`csrf.token` 的公开桩；初始状态下每个测试都会在
第一次调用桩时因 ``NotImplementedError`` 失败。测试不读取系统时间、不使用随机
数，所有密钥、nonce 与时间戳均为固定值。
"""

from csrf import token

SECRET = "0123456789abcdef0123456789abcdef"  # 32 UTF-8 bytes
NONCE_A = "0123456789abcdef"
NONCE_B = "fedcba9876543210"


def _tamper_last_char(value: str) -> str:
    """确定性地改动 token 的最后一个字符，保持长度与字段形状不变。"""
    replacement = "0" if value[-1] != "0" else "1"
    return value[:-1] + replacement


# ---------------------------------------------------------------------------
# 10 个缺陷：每条测试对应一个必须修复的安全缺陷。
# ---------------------------------------------------------------------------

def test_issue_binds_token_to_session_id():
    """缺陷 1：issue 若不把 session_id 纳入 MAC，A 的 token 会等于 B 的。"""
    alice = token.issue(SECRET, "alice", NONCE_A, 1000)
    bob = token.issue(SECRET, "bob", NONCE_A, 1000)

    assert len(alice) == token.TOKEN_LENGTH == 95
    assert len(bob) == 95
    assert alice != bob
    # 同 nonce、同时间戳时，只有 MAC 能体现用户绑定。
    assert alice.split(":")[3] != bob.split(":")[3]


def test_verify_interprets_timestamp_as_seconds_with_exact_ttl():
    """缺陷 2：签发用秒而校验按毫秒会导致瞬过期或永不过期。"""
    issued_at = 1000
    issued = token.issue(SECRET, "d2-user", NONCE_A, issued_at)

    assert issued.split(":")[1] == "0000001000"
    assert token.verify(SECRET, "d2-user", issued, issued_at) is True
    assert token.verify(SECRET, "d2-user", issued, issued_at + 300) is True
    assert token.verify(SECRET, "d2-user", issued, issued_at + 301) is False


def test_verify_uses_constant_time_signature_comparison(monkeypatch):
    """缺陷 3：verify 用 == 比较签名会泄露时序信息。"""
    calls = []
    real_compare_digest = token.hmac.compare_digest

    def recording_compare_digest(left, right):
        calls.append((left, right))
        return real_compare_digest(left, right)

    monkeypatch.setattr(token.hmac, "compare_digest", recording_compare_digest)

    issued = token.issue(SECRET, "d3-user", NONCE_A, 7000)
    calls.clear()

    assert token.verify(SECRET, "d3-user", issued, 7000) is True
    forged = _tamper_last_char(issued)
    assert token.verify(SECRET, "d3-user", forged, 7000) is False

    assert len(calls) >= 2
    assert any(left != right for left, right in calls)


def test_verify_rejects_well_formed_forged_signature():
    """缺陷 4：verify 只校验格式而不验签时，伪造签名会被放行。"""
    issued = token.issue(SECRET, "d4-user", NONCE_A, 7500)
    version, timestamp, nonce, _signature = issued.split(":")
    forged = f"{version}:{timestamp}:{nonce}:{'0' * 64}"

    assert len(forged) == 95
    assert token.verify(SECRET, "d4-user", forged, 7500) is False


def test_double_submit_rejects_matching_but_unsigned_tokens():
    """缺陷 5：double_submit 若只比较字符串，两处同时伪造即可绕过。"""
    forged = f"v1:0000003000:{NONCE_A}:{'0' * 64}"

    assert len(forged) == 95
    assert token.double_submit(SECRET, forged, forged, "d5-user") is False


def test_double_submit_rejects_cookie_token_from_other_session():
    """缺陷 6：double_submit 若不校验 cookie token 的会话绑定，跨会话通过。"""
    issued = token.issue(SECRET, "d6-alice", NONCE_A, 3000)

    assert token.double_submit(SECRET, issued, issued, "d6-alice") is True
    assert token.double_submit(SECRET, issued, issued, "d6-bob") is False


def test_rotate_invalidates_previous_token_for_replay():
    """缺陷 7：rotate 不记录旧 token 时，旧 token 仍可重放。"""
    old = token.issue(SECRET, "d7-rotate", NONCE_A, 2000)
    new = token.rotate(SECRET, "d7-rotate", 2001)

    assert len(new) == 95
    assert new != old
    assert token.verify(SECRET, "d7-rotate", old, 2002) is False
    assert token.verify(SECRET, "d7-rotate", new, 2002) is True
    assert token.double_submit(SECRET, old, old, "d7-rotate") is False
    assert token.double_submit(SECRET, new, new, "d7-rotate") is True


def test_nonce_for_is_deterministic_but_session_scoped():
    """缺陷 8：nonce 只用 counter 会让不同会话在同一 counter 上碰撞。"""
    alice_nonce = token.nonce_for("d8-alice", 7)
    bob_nonce = token.nonce_for("d8-bob", 7)

    assert alice_nonce == token.nonce_for("d8-alice", 7)
    assert len(alice_nonce) == 16
    assert set(alice_nonce) <= set("0123456789abcdef")
    assert alice_nonce != bob_nonce


def test_ttl_ok_rejects_negative_ttl_and_config_flags_bad_values():
    """缺陷 9：负 TTL 若被当作无限有效期，token 永不失效。"""
    assert token.ttl_ok(1000, 1000, 300) is True
    assert token.ttl_ok(700, 1000, 300) is True
    assert token.ttl_ok(699, 1000, 300) is False
    assert token.ttl_ok(1001, 1000, 300) is False
    assert token.ttl_ok(1000, 1000, 0) is False
    assert token.ttl_ok(1000, 1000, -1) is False

    bad_config = {"secret": "short", "ttl": 301, "compare": "=="}
    assert token.validate_config(bad_config) == [
        "secret_too_short",
        "ttl_out_of_range",
        "compare_not_constant_time",
    ]
    good_config = {"secret": SECRET, "ttl": 300, "compare": "compare_digest"}
    assert token.validate_config(good_config) == []


def test_csrf_batch_never_reuses_first_request_token():
    """缺陷 10：批量校验复用状态时，第二个请求会命中第一个请求的 token。"""
    config = {"secret": SECRET, "ttl": 300, "compare": "compare_digest"}
    first_token = token.issue(SECRET, "d10-shared", NONCE_A, 3000)
    second_token = token.issue(SECRET, "d10-other", NONCE_B, 3000)
    requests = [
        {
            "id": "first",
            "session_id": "d10-shared",
            "cookie_token": first_token,
            "form_token": first_token,
            "now": 3000,
        },
        {
            "id": "second",
            "session_id": "d10-other",
            "cookie_token": second_token,
            "form_token": first_token,
            "now": 3000,
        },
        {
            "id": "third",
            "session_id": "d10-other",
            "cookie_token": first_token,
            "form_token": first_token,
            "now": 3000,
        },
    ]

    assert token.csrf_batch(requests, config) == {
        "first": True,
        "second": False,
        "third": False,
    }


# ---------------------------------------------------------------------------
# 另外 5 条：正向路径、篡改、过期、跨用户、批量与单条一致性。
# ---------------------------------------------------------------------------

def test_valid_token_passes_round_trip():
    """正确签发的 token 应同时通过 verify 与双提交校验。"""
    issued = token.issue(SECRET, "e1-user", NONCE_A, 8000)

    assert len(issued) == 95
    assert token.verify(SECRET, "e1-user", issued, 8000) is True
    assert token.double_submit(SECRET, issued, issued, "e1-user") is True


def test_single_character_tamper_is_rejected():
    """只改动签名的一位也必须被拒绝。"""
    issued = token.issue(SECRET, "e2-user", NONCE_A, 4000)
    tampered = _tamper_last_char(issued)

    assert tampered != issued
    assert len(tampered) == len(issued) == 95
    assert token.verify(SECRET, "e2-user", tampered, 4000) is False
    assert token.double_submit(SECRET, tampered, tampered, "e2-user") is False


def test_expired_token_is_rejected():
    """超过 300 秒 TTL 的 token 必须被拒绝。"""
    issued = token.issue(SECRET, "e3-user", NONCE_A, 9000)

    assert token.verify(SECRET, "e3-user", issued, 9000) is True
    assert token.verify(SECRET, "e3-user", issued, 9301) is False


def test_cross_user_token_is_rejected():
    """一个用户的有效 token 不能用于另一个用户。"""
    alice = token.issue(SECRET, "e4-alice", NONCE_A, 5000)
    bob = token.issue(SECRET, "e4-bob", NONCE_B, 5000)

    assert token.verify(SECRET, "e4-alice", bob, 5000) is False
    assert token.double_submit(SECRET, alice, bob, "e4-alice") is False


def test_batch_validation_matches_individual_validation():
    """每个请求的批量结果必须等于单独调用 double_submit 与 verify 的结果。"""
    config = {"secret": SECRET, "ttl": 300, "compare": "compare_digest"}
    valid = token.issue(SECRET, "e5-valid", NONCE_A, 6000)
    expired = token.issue(SECRET, "e5-expired", NONCE_A, 6000)

    requests = [
        {
            "id": "valid",
            "session_id": "e5-valid",
            "cookie_token": valid,
            "form_token": valid,
            "now": 6000,
        },
        {
            "id": "expired",
            "session_id": "e5-expired",
            "cookie_token": expired,
            "form_token": expired,
            "now": 6301,
        },
    ]

    expected = {
        request["id"]: (
            token.double_submit(
                SECRET,
                request["cookie_token"],
                request["form_token"],
                request["session_id"],
            )
            and token.verify(
                SECRET,
                request["session_id"],
                request["cookie_token"],
                request["now"],
            )
        )
        for request in requests
    }

    assert expected == {"valid": True, "expired": False}
    assert token.csrf_batch(requests, config) == expected
