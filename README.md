表单加了 CSRF token，跨站提交却还是成功，日志里 token 一直是同一个：签发只用时间戳和随机数，没有绑定会话，A 的 token 可以给 B 用；签发用秒级时间戳，校验按毫秒比较，过期判定完全错位；签名比较用普通的等号判断，不是恒定时间比较；校验只看格式不看签名，任意构造的 token 都能通过；双提交只比较两个 token 是否相等，不做验签，攻击者可以同时伪造两边；双提交不检查 Cookie 里的 token 与会话的绑定关系；轮换生成新 token 但不记录旧 token，旧 token 还能重放；随机数只依赖计数器，多个用户之间会撞同一个值；时间窗判定允许负的有效期，token 永不失效；批量校验复用密钥与状态，后一个请求命中前一个请求的 token。csrf/token.py 是核心，tests/test_token.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

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
