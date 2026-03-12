APP_ABI       := arm64-v8a
APP_PLATFORM  := android-21
APP_STL       := c++_static
APP_OPTIM     := release
APP_PIE       := true

ifeq ($(APP_OPTIM),release)
    APP_CFLAGS     := -O2 -DNDEBUG
    APP_STRIP_MODE := --strip-all
else
    APP_CFLAGS     := -O0 -g
    APP_STRIP_MODE := none
endif

APP_CPPFLAGS := -std=c++17 -fexceptions -frtti
APP_BUILD_SCRIPT := jni/Android.mk
