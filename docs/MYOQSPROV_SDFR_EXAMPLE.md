# myoqsprov + SDFR/SDFU 示例（ML-DSA + ML-KEM）

## 1) 先决条件

- `libuci.so` 已构建完成（本仓 `build/libuci.so`）
- `test_sdfr_pq` 已编译（本仓 `build/test_sdfr_pq`）
- provider 模块文件存在：`myoqsprov.so`
- `myoqsprov.so` 运行时可找到 `liboqs.so.9`

可检查：

```bash
ldd /path/to/myoqsprov.so
```

应看到：`liboqs.so.9 => /usr/local/lib/liboqs.so.9`（或你的安装路径）

## 2) 运行示例

```bash
cd /root/project/apidesign-uci-source

export OPENSSL_MODULES=/root/project/myoqsprov
export LD_LIBRARY_PATH=/root/project/apidesign-uci-source/build:/usr/local/lib:$LD_LIBRARY_PATH
export UCI_TEST_PROVIDER=myoqsprov

./build/test_sdfr_pq
```

## 3) 期望输出

```text
[PASS] SDFR ML-DSA sign/verify + ML-KEM encap/decap via provider=myoqsprov
```

并且退出码为 `0`。

## 4) 失败排查

- 若 provider 加载失败：检查 `OPENSSL_MODULES` 和 `myoqsprov.so` 文件名/路径
- 若算法拉取失败：检查 properties 是否为 `provider=myoqsprov`
- 若链接失败：检查 `LD_LIBRARY_PATH` 与 `liboqs.so.9`

## 5) 示例中使用的路由映射

测试会临时写入 `SDFR_PATCH_FILE`：

- `0x00F0D501 -> mldsa65 provider=myoqsprov`
- `0x00F0D502 -> mlkem768 provider=myoqsprov`

