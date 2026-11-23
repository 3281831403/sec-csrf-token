表单加了 CSRF token，跨站提交却还是成功，日志里 token 一直是同一个：`issue` 只用时间戳和 nonce 做 HMAC，没有把 `session_id` 纳入签名，A 用户的 token 能直接给 B 用；`issue` 写入秒级时间戳，`verify` 却按毫秒比较，token 要么瞬间过期要么长期不过期；`verify` 用 `==` 比较签名，存在可被利用的时序侧信道；`verify` 只看 token 的字段格式、不重新计算 HMAC，任意形状正确的伪造 token 都能通过；`double_submit` 只比较 cookie 与表单两个字符串是否相等，不验签，攻击者同时伪造两处即可；`double_submit` 不核对 cookie token 与 `session_id` 的绑定，跨会话也能通过；`rotate` 生成了新 token 却不记录旧 token 的撤销下限，旧 token 仍可重放；`nonce_for` 只用 `counter` 计算，多个会话在同一 counter 上得到相同 nonce；`ttl_ok` 对负 TTL 不做拒绝，等价于永不失效；`csrf_batch` 复用 secret 和首个请求的 token 状态，第二个请求会误中第一个请求的 token。csrf/token.py 是核心，tests/test_token.py 15个红。要修的是：恢复 session 绑定、统一秒级时间窗、改用 `hmac.compare_digest`、完整验签、双提交验签、双提交会话绑定、轮换时撤销旧 token、让 nonce 带会话作用域、拒绝负 TTL、隔离批量请求。

## 运行方式

在仓库根目录执行，不需要安装、联网或启动服务：

```powershell
cd D:\gsb-20261119\sec-csrf-token
python -m pytest tests -q
```

初始状态必须恰好有 **15 failed**，且没有 collection error、import error 或 syntax error。输出末行形如：

```text
15 failed in 0.03s
```

`csrf/token.py` 里 8 个函数目前全部是 `raise NotImplementedError`，所以每个测试都会在第一次调用公开函数时失败。实现时只替换这些函数体，不要改函数签名，也不要把测试改成跳过或通过。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 契约

- token 固定为 95 个字符：`v1:<ts10>:<nonce16>:<mac64>`。`ts10` 是 10 位十进制 Unix **秒**；`nonce16` 是 16 位小写十六进制；`mac64` 是 64 位小写十六进制 HMAC-SHA256。
- 签名输入为 `v1:<session_id>:<ts10>:<nonce16>`，密钥为 `secret.encode("utf-8")`。`session_id` 必须进入 MAC，token 不得跨用户复用。
- TTL 固定 **300 秒且包含边界**：`now - ts == 300` 有效，`301` 无效。**时钟容差为 0 秒**，未来时间戳也拒绝。
- 签名相等性只能使用 `hmac.compare_digest`；`==` 不可用于签名比较。
- 双提交要求 cookie token 与 form token 完全相同，且两者都是绑定当前 `session_id` 的有效签名；该函数没有 `now` 参数，因此不单独判定 TTL。
- `rotate` 维护内存态撤销下限：调用后 `verify`、`double_submit`、`csrf_batch` 都必须拒绝时间戳早于该下限的旧 token。`now` 必须严格大于该会话当前下限。
- 配置为 `{"secret": str, "ttl": int, "compare": "compare_digest"}`；secret 至少 32 个 UTF-8 字节，ttl 在 1..300，compare 必须为 `"compare_digest"`。
- 批量请求为 `{"id": str, "session_id": str, "cookie_token": str, "form_token": str, "now": int}`，返回 `{id: bool}`；每个请求独立解析和校验，不能缓存或复用请求 token。

## 文件

```text
sec-csrf-token/
├── README.md
├── conftest.py
├── .gitignore
├── csrf/
│   ├── __init__.py
│   └── token.py
└── tests/
    └── test_token.py
```

## tests 不可修改

`tests/test_token.py` 是验收标准，不可修改、删除、跳过、参数化替换或放宽。不要改动测试中的固定密钥、nonce、时间戳和断言；只能实现 `csrf/token.py`。
