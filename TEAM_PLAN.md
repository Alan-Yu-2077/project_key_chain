# 分工方案 · Project 2 密码管理器

> 截止：**11 月 12 日（周四）当天结束前**。
> 评分：四个构件能用 40% · README 讲清"为什么" 40% · 安全模型 10% · 代码质量+加分项 10%。

## 1. 分工

| 人 | 负责 |
|---|---|
| **Alan（主力）** | 架构和整体逻辑；与 Claude 一起完成全部代码和测试；用自己的话写 README 里的五个"为什么"和安全模型；合并 PR |
| **成员 B、C（审阅）** | 用自己的 GitHub 账号 review 每一个 PR（提问、提意见、approve）；审读 README；准备答辩 |

**为什么审阅不是走过场**：作业允许用 AI 写代码，但答辩时组里**任何一个人**都可能被要求解释**任何一行**密码学代码。对 B 和 C 来说，PR review 就是读懂代码的主要途径。

- 每个 PR 必须 **B 和 C 都 approve** 才能合并。
- 代码以 Alan 的身份提交，commit 末尾带 `Co-Authored-By: Claude`。任何人都不以别人的名义提交，B、C 的贡献如实体现在 PR review 记录里。

### 审阅时要做到的事

1. 对 PR 里每个函数，能用自己的话说出它**做了什么、为什么这样做**。说不出来就在 PR 里提问，直到能说出来为止，这本身就是答辩准备。
2. 核对参数（盐长度、nonce 长度、Argon2 参数）和文档、README 是否一致。
3. 确认测试覆盖了对应的验收标准（见第 5 节）。
4. 留意有没有用 `random`、有没有把密码打印出来、写入磁盘或放进命令行参数。

## 2. PR 拆分（依次合并）

| PR | 分支 | 内容 | 审阅重点 |
|---|---|---|---|
| 1 | `feat/vault-core` | 项目骨架、`errors.py`、`crypto.py`、`store.py`、验收测试 1–3 | Argon2 的两种用法（存哈希 vs 派生密钥）有何区别；AAD 的作用；为什么每次保存都要新 nonce；为什么改动任意一个字节都一定报错 |
| 2 | `feat/cli` | `generator.py`、`cli.py`、入口 `vault.py`、验收测试 4 | 为什么用 `secrets` 不用 `random`；为什么密码不走命令行参数；错误提示是否清楚 |
| 3 | `feat/hibp` | 加分项：HIBP 泄露检查 | 到底发出去了什么；为什么只发 SHA-1 前 5 位是安全的 |
| 4 | `docs/readme` | README（Alan 写） | 每个"为什么"是否正确、是否是我们自己的话 |

## 3. 时间线

| 日期 | 事项 |
|---|---|
| **11/8 周日** | Alan + Claude 完成全部代码和测试，开 PR 1 |
| **11/9 周一** | B、C review PR 1；Alan 修改后合并，开 PR 2、PR 3 |
| **11/10 周二** | B、C review PR 2、PR 3，合并；Alan 写 README 初稿，开 PR 4 |
| **11/11 周三** | B、C 审读 README。**答辩演练**：B 讲 `crypto.py` + `store.py`，C 讲 `cli.py` + `generator.py` + `hibp.py`，Alan 提问 |
| **11/12 周四** | 冻结，只修 bug；对照第 5 节逐条打勾；打 tag 提交 |

## 4. 整体逻辑与 vault 文件格式（全员必须看懂）

```text
init   : getpass 两次 → hash_master_password(pw)        （argon2-cffi，生成 "$argon2id$..."，自带一份随机盐）
         → salt = 16 字节随机数                          （KDF 专用，和上面那份盐相互独立）
         → key = derive_key(pw, salt)                    （cryptography 的 Argon2id KDF，32 字节）
         → encrypt(key, 条目 JSON, aad=头部) → 原子写入
unlock : 读文件 → 严格解析（必须是规范格式）
         → verify_master_password（失败 → WrongMasterPassword）
         → key = derive_key(pw, salt) → decrypt（GCM 认证失败 → VaultCorrupted）→ 条目
save   : 新的 12 字节随机 nonce → encrypt(key, 条目 JSON, aad=头部) → 临时文件 + os.replace
```

```json
{
  "cipher": "aes-256-gcm",
  "ciphertext": "<base64：AES-GCM 密文 + 16 字节认证标签>",
  "kdf": {
    "alg": "argon2id",
    "memory_cost": 65536,
    "parallelism": 4,
    "salt": "<base64：16 字节>",
    "time_cost": 3
  },
  "master_hash": "$argon2id$v=19$m=65536,t=3,p=4$...",
  "nonce": "<base64：12 字节>",
  "version": 1
}
```

- 磁盘上**没有任何密钥**。密钥只存在于内存，每次解锁都由主密码重新派生。
- **头部**（`cipher`、`kdf`、`master_hash`、`version`）作为 AES-GCM 的附加认证数据（AAD），改动头部的任何内容都会导致解密失败。`nonce` 和 `ciphertext` 由 GCM 标签本身保护。
- 解析器只接受**逐字节规范**的文件（键排序、固定缩进、规范 base64）。这样 JSON 空白、base64 填充位这类"改了也解码出同样内容"的字节也逃不过检测。
- 即使攻击者把 `master_hash` 换成他自己密码的哈希也没用：校验虽然能通过，但派生出的密钥不对，GCM 解密照样失败。存储的哈希只用来给出"密码错误"的明确提示，真正的保护来自密钥派生加 GCM。

## 5. 验收清单（全部有自动化测试，提交前全员再手动过一遍）

- [ ] vault 文件里存的主密码值以 `$argon2id$` 开头 → `tests/test_acceptance.py`
- [ ] 错误主密码被拒绝，给出明确提示 → `tests/test_acceptance.py`、`tests/test_cli.py`
- [ ] 目录里除了 vault 文件没有任何密钥文件；重新打开只需要主密码 → `tests/test_acceptance.py`
- [ ] 对 vault 文件**每个字节的每一位**逐一翻转，每次都明确报错 → `tests/test_acceptance.py`
- [ ] 生成器只用 `secrets`，全项目不导入 `random`；长度可选，字符集宽 → `tests/test_generator.py`
- [ ] README 回答了 Q1–Q5，写明用了哪个库以及为什么；安全模型至少列出键盘记录器、弱主密码、屏幕被人看到
- [ ] 加分项 HIBP 可用，README 解释了为什么只发 SHA-1 前 5 位是安全的 → `tests/test_hibp.py`
