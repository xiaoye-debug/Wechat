TARGET := iphone:clang:latest:15.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES := WeChat

include $(THEOS)/makefiles/common.mk

TWEAK_NAME := WeChatEnvBypass
WeChatEnvBypass_FILES := Tweak.x
WeChatEnvBypass_CFLAGS := -fobjc-arc
WeChatEnvBypass_FRAMEWORKS := Foundation CoreFoundation UIKit
# Only Objective-C method hooks are used. The internal generator avoids a
# Substrate/libhooker/ElleKit dependency when the dylib is embedded in an IPA.
WeChatEnvBypass_LOGOS_DEFAULT_GENERATOR := internal

include $(THEOS_MAKE_PATH)/tweak.mk
