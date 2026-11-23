"""CSRF token 契约与待实现桩。

本模块只使用标准库 ``hmac``、``hashlib``，不读取系统时间、不使用随机源。
所有时间参数都由调用方显式传入，单位统一为 Unix 秒。

固定 token 格式（总长度恰好 95 个字符）::

    v1:<ts10>:<nonce16>:<mac64>

* ``v1``      : 协议版本，2 字符。
* ``ts10``    : ``now`` 的 10 位十进制 Unix 秒，不足左补 0。
* ``nonce16`` : 16 位小写十六进制 nonce。
* ``mac64``   : 64 位小写十六进制 HMAC-SHA256 签名。

签名输入::

    v1:<session_id>:<ts10>:<nonce16>

HMAC 密钥为 ``secret.encode("utf-8")``。由于 token 本身不存放 session_id，
session_id 必须进入 MAC，否则 token 会失去用户绑定。

安全常量：token 长度 95；TTL 300 秒（包含边界）；签名比较方式为
``hmac.compare_digest``；时钟容差为 0 秒。八个函数目前全部是桩：实现时只替换
对应函数体中的桩语句，不要修改公开签名。
"""

from __future__ import annotations

import hashlib
import hmac

TOKEN_PREFIX = "v1"
TOKEN_LENGTH = 95
TIMESTAMP_WIDTH = 10
NONCE_LENGTH = 16
MAC_LENGTH = 64
TOKEN_TTL = 300
MIN_SECRET_BYTES = 32
MAX_TTL = 300
CONSTANT_TIME_COMPARE = "compare_digest"


def issue(secret: str, session_id: str, nonce: str, now: int) -> str:
    """签发一个绑定到 ``session_id`` 的 95 字符 CSRF token。

    返回格式严格为 ``v1:<ts10>:<nonce16>:<mac64>``：

    * ``ts10`` 是 ``now`` 的 10 位十进制表示，单位是**秒**，不是毫秒；
    * ``nonce16`` 原样使用调用方传入的 16 位小写十六进制 nonce；
    * ``mac64`` 是
      ``HMAC-SHA256(secret.encode("utf-8"),
      f"v1:{session_id}:{ts10}:{nonce16}".encode("utf-8")).hexdigest()``。

    契约：token 长度必须恰好 95；TTL 为 300 秒（含边界）；签名比较必须使用
    ``hmac.compare_digest``；时钟容差为 0 秒。不得使用随机数、系统时间或隐式
    nonce，相同参数必须得到相同 token。

    参数约束：``secret`` 为非空 str；``session_id`` 匹配
    ``[A-Za-z0-9._-]{1,64}``；``nonce`` 恰好 16 位小写十六进制；``now`` 是
    0..9_999_999_999 范围内的 int（``bool`` 不算 int）。违反约束抛
    ``ValueError``。
    """
    raise NotImplementedError


def verify(secret: str, session_id: str, token: str, now: int) -> bool:
    """在 ``now`` 时刻校验 token；通过返回 True，否则返回 False。

    校验步骤与契约：

    * 严格解析 95 字符的 ``v1:<ts10>:<nonce16>:<mac64>``，字段必须都是规定
      长度的小写十六进制/十进制；
    * 用 ``session_id``、时间戳与 nonce 重新计算 HMAC-SHA256，并且仅用
      ``hmac.compare_digest`` 比较 64 位签名，禁止用 ``==`` 比较签名；
    * 时间戳按 Unix **秒**解释（不是毫秒），年龄必须满足
      ``ttl_ok(ts, now, TOKEN_TTL)``；
    * TTL 固定 300 秒，``now - ts == 300`` 仍有效，``301`` 无效；容差为
      0 秒，未来时间戳也拒绝；
    * token 的 MAC 必须绑定 ``session_id``，不能跨用户复用；
    * 若该 ``(secret, session_id)`` 被 :func:`rotate` 推进过撤销下限，则
      ``ts`` 早于下限的 token 无效；
    * 畸形输入、错误类型、空值一律返回 False，不抛异常。
    """
    raise NotImplementedError


def double_submit(secret: str, cookie_token: str, form_token: str,
                  session_id: str) -> bool:
    """双提交校验：两个 token 相同且都是绑定当前会话的有效签名。

    通过条件（全部满足）：

    * ``cookie_token`` 与 ``form_token`` 都是 str，非空且完全相等；相等比较也
      使用 ``hmac.compare_digest``；
    * 两个值都必须能解析成 95 字符 token，且重新计算的 HMAC 用
      ``hmac.compare_digest`` 比较为真；
    * MAC 必须绑定 ``session_id``，不能接受其他会话签发的 token；
    * token 的时间戳不得早于该会话的轮换撤销下限。

    本函数没有 ``now`` 参数，因此只验签、绑定与撤销状态，不判定 TTL；过期判定由
    :func:`verify` 或 :func:`csrf_batch` 完成。畸形输入返回 False，不抛异常。
    """
    raise NotImplementedError


def rotate(secret: str, session_id: str, now: int) -> str:
    """轮换会话 token，返回新 token，并使旧 token 失效。

    实现语义：

    * 用 ``nonce_for(session_id, now)`` 作为 nonce，按 :func:`issue` 的算法签发
      一个 95 字符新 token；
    * 模块维护内存态撤销下限，键为 secret 指纹与 session_id；调用后把下限推进到
      ``now``。:func:`verify`、:func:`double_submit` 和 :func:`csrf_batch` 必须
      拒绝时间戳早于该下限的 token；
    * ``now`` 必须严格大于该会话当前下限，否则抛 ``ValueError``；因此旧 token
      的时间戳应早于 ``now``。同秒旧 token 要等到下一次不同秒轮换才会被撤销；
    * 不使用随机源，不读取系统时间；一次调用的结果由参数和当前内存态确定。

    参数约束与 :func:`issue` 相同。新 token 的 TTL 仍为 300 秒，签名比较方式仍为
    ``hmac.compare_digest``，时钟容差仍为 0 秒。
    """
    raise NotImplementedError


def nonce_for(session_id: str, counter: int) -> str:
    """确定性地生成 16 位小写十六进制 nonce。

    计算公式::

        hashlib.sha256(f"{session_id}:{counter}".encode("utf-8")).hexdigest()[:16]

    契约：相同 ``session_id`` 与 ``counter`` 必须得到相同结果；不同会话即使
    ``counter`` 相同也必须得到不同 nonce，避免多个用户共享同一 nonce 造成重放
    碰撞。``session_id`` 约束同 :func:`issue`；``counter`` 必须是非负 int
    （``bool`` 不算 int），否则抛 ``ValueError``。

    本函数不使用随机源或系统时间；调用方应在会话内单调递增 ``counter``。
    """
    raise NotImplementedError


def ttl_ok(ts: int, now: int, ttl: int) -> bool:
    """判断时间戳 ``ts`` 在 ``now`` 时刻是否落在 TTL 窗口内。

    仅当满足以下全部条件时返回 True：

    * ``ts``、``now`` 是非负 int（``bool`` 不算 int）；
    * ``ttl`` 是 1..300 范围内的 int；
    * ``0 <= now - ts <= ttl``。

    边界：``now - ts == ttl`` 仍有效；``now - ts > ttl`` 无效；未来时间戳
    （``now - ts < 0``）一律无效。``ttl <= 0``（含负数）无效，不能把非正 TTL
    解释成无限有效期。时钟偏移容差固定为 **0 秒**，本函数不提供 skew 参数。
    """
    raise NotImplementedError


def validate_config(config: dict) -> list[str]:
    """检查 CSRF 配置，返回固定顺序的问题代码列表。

    合法配置返回 ``[]``。问题代码只有以下三个，按顺序追加且不重复：

    * ``"secret_too_short"``：``config["secret"]`` 不是 str，或其 UTF-8 编码
      少于 32 字节；
    * ``"ttl_out_of_range"``：``config["ttl"]`` 不是 int（bool 不算），或不在
      1..300 范围内；
    * ``"compare_not_constant_time"``：``config["compare"]`` 不等于
      ``"compare_digest"``。

    缺失字段按对应问题处理；``config`` 不是映射时返回全部三个问题代码。本函数
    只返回问题列表，不抛异常。比较方式非恒定时间属于必须拦截的安全配置错误。
    """
    raise NotImplementedError


def csrf_batch(requests: list[dict], config: dict) -> dict:
    """批量校验请求，每个请求完全独立，返回 ``{request_id: bool}``。

    ``config`` 形如::

        {"secret": "至少32字节的密钥", "ttl": 300, "compare": "compare_digest"}

    先调用 :func:`validate_config`；若配置有问题，所有能识别出 id 的请求都返回
    False，绝不让坏配置放行。

    每个请求是映射::

        {"id": "r1", "session_id": "s1",
         "cookie_token": "...", "form_token": "...", "now": 1700000000}

    单条请求返回 True 当且仅当：

    * ``double_submit(secret, cookie_token, form_token, session_id)`` 为 True；
    * 从**该请求自己的** ``cookie_token`` 中解析出的时间戳 ``ts`` 满足
      ``ttl_ok(ts, request["now"], config["ttl"])``。

    契约：token 长度 95；TTL 从 config 读取；比较方式为
    ``hmac.compare_digest``；时钟容差为 0 秒。每个请求必须重新读取自己的 token
    与 now，禁止缓存、复用或让后一个请求命中前一个请求的 token/结果；除只读
    secret 外，请求之间不得共享状态。字段缺失/类型错误使该 id 为 False；id 缺失
    或重复抛 ``ValueError``。
    """
    raise NotImplementedError
