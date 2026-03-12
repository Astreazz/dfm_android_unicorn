LOCAL_PATH := $(call my-dir)

# ============================================================
# Prebuilt Unicorn Engine (ARM64 static libraries)
# Built from unicorn 2.x for Android arm64-v8a
# ============================================================
include $(CLEAR_VARS)
LOCAL_MODULE := unicorn-static
LOCAL_SRC_FILES := libs/$(TARGET_ARCH_ABI)/libunicorn-static.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := unicorn-common
LOCAL_SRC_FILES := libs/$(TARGET_ARCH_ABI)/libunicorn-common.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := aarch64-softmmu
LOCAL_SRC_FILES := libs/$(TARGET_ARCH_ABI)/libaarch64-softmmu.a
include $(PREBUILT_STATIC_LIBRARY)

# ============================================================
# Standalone executable (for testing)
# ============================================================
include $(CLEAR_VARS)
LOCAL_MODULE := sjz_decrypt_arm64

LOCAL_SRC_FILES := sjz_dec_arm64.cpp auto_finder_arm64.cpp main.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES := unicorn-static unicorn-common aarch64-softmmu
LOCAL_WHOLE_STATIC_LIBRARIES := aarch64-softmmu

LOCAL_CPPFLAGS := -std=c++17 -fexceptions -O2 -fno-rtti \
    -DANDROID_ARM64

LOCAL_LDLIBS := -llog

include $(BUILD_EXECUTABLE)

# ============================================================
# Shared library (for integration with UE4Dump SDK)
# ============================================================
include $(CLEAR_VARS)
LOCAL_MODULE := libsjz_decrypt

LOCAL_SRC_FILES := sjz_dec_arm64.cpp auto_finder_arm64.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES := unicorn-static unicorn-common aarch64-softmmu
LOCAL_WHOLE_STATIC_LIBRARIES := aarch64-softmmu

LOCAL_CPPFLAGS := -std=c++17 -fexceptions -O2 -fno-rtti \
    -DANDROID_ARM64 -DSJZ_BUILD_SHARED

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
