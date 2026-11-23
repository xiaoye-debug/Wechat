# 构建依据

本项目使用固定 Theos 提交 `8167f59de02fd32cf45b16bfcb1330dfa5c9974c`，构建依赖及接口依据如下：

- [Theos tweak 规则](https://github.com/theos/theos/blob/8167f59de02fd32cf45b16bfcb1330dfa5c9974c/makefiles/instance/tweak.mk)：`WeChatEnvBypass_LOGOS_DEFAULT_GENERATOR` 会传给 Logos，可选择 `internal`；默认生成器是 MobileSubstrate。
- [Theos Darwin 动态库规则](https://github.com/theos/theos/blob/8167f59de02fd32cf45b16bfcb1330dfa5c9974c/makefiles/targets/_common/darwin_head.mk)：`TARGET_LDFLAGS_DYNAMICLIB` 默认使用安装路径作为动态库 ID。本项目覆盖为 `@rpath`，并通过真实 Mach-O load command 校验依赖。
- [Theos library 打包规则](https://github.com/theos/theos/blob/8167f59de02fd32cf45b16bfcb1330dfa5c9974c/makefiles/instance/library.mk)：从 staging 目录导出已处理的动态库，再将 DEB 解包与其逐字节比较，避免发布未经最终处理的中间对象。

这些资料解释构建行为，不证明 iOS 27、微信当前版本或用户签名证书可用。没有上传 IPA、私钥、证书或描述文件。
