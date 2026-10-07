#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#include "fishhook.h"

#pragma mark - Original function pointers

static char *(*orig_getenv)(const char *name);
static const char *(*orig_dyld_get_image_name)(uint32_t image_index);
static NSString *(*orig_bundleIdentifier)(id self, SEL _cmd);

#pragma mark - Config

// 需要隐藏的注入特征关键词
static const char *kHiddenKeywords[] = {
    "AntiDetection",
    "libMediaUtility",
    "YourInjectedPlugin",
    "tweak",
    "Substrate",
    NULL
};

// 强制返回的原版 Bundle ID（多开伪装）
static NSString *const kSpoofedBundleIdentifier = @"com.leoao.mobileapp";

// 伪装后的合法 mobileprovision 文件名（签名校验拦截）
static NSString *const kSpoofedProvisioningProfile = @"embedded.mobileprovision";

#pragma mark - Anti-detect: Hook getenv

// 隐藏 DYLD_INSERT_LIBRARIES 环境变量
static char *custom_getenv(const char *name) {
    if (name != NULL) {
        NSString *envName = [NSString stringWithUTF8String:name];
        if ([envName isEqualToString:@"DYLD_INSERT_LIBRARIES"]) {
            NSLog(@"[AntiDetect] Intercepted getenv(DYLD_INSERT_LIBRARIES), returning NULL");
            return NULL;
        }
    }
    return orig_getenv(name);
}

#pragma mark - Anti-detect: Hook dyld image enumeration

// 隐藏注入 dylib 的镜像路径
static const char *custom_dyld_get_image_name(uint32_t image_index) {
    const char *imageName = orig_dyld_get_image_name(image_index);
    if (imageName == NULL) {
        return imageName;
    }

    NSString *path = [NSString stringWithUTF8String:imageName];
    for (int i = 0; kHiddenKeywords[i] != NULL; i++) {
        NSString *kw = [NSString stringWithUTF8String:kHiddenKeywords[i]];
        if ([path rangeOfString:kw options:NSCaseInsensitiveSearch].location != NSNotFound) {
            // 伪装成系统合法路径返回（静态字符串，生命周期安全）
            return "/usr/lib/libSystem.B.dylib";
        }
    }
    return imageName;
}

#pragma mark - Multi-open spoof: Hook NSBundle bundleIdentifier

// 强制主 Bundle 返回原版标识
static NSString *custom_bundleIdentifier(id self, SEL _cmd) {
    // 只劫持 mainBundle，避免影响系统框架
    if (self == [NSBundle mainBundle]) {
        return kSpoofedBundleIdentifier;
    }
    return orig_bundleIdentifier(self, _cmd);
}

#pragma mark - Signature/provisioning intercept: Hook open/read of embedded.mobileprovision

// 拦截对签名文件（embedded.mobileprovision）的访问
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
static int (*orig_open)(const char *path, int oflag, ...);
static int custom_open(const char *path, int oflag, ...) {
    if (path != NULL) {
        NSString *p = [NSString stringWithUTF8String:path];
        // 拦截 embedded.mobileprovision 读取，伪装为文件不存在
        if ([p rangeOfString:kSpoofedProvisioningProfile].location != NSNotFound) {
            NSLog(@"[AntiDetect] Intercepted open(%@)", p);
            errno = ENOENT;
            return -1;
        }
    }
    // 正确转发变参（mode），仅在 O_CREAT 时需要
    if (oflag & O_CREAT) {
        va_list ap;
        va_start(ap, oflag);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return orig_open(path, oflag, mode);
    }
    return orig_open(path, oflag);
}

#pragma mark - Init

__attribute__((constructor))
static void AntiDetectionInit(void) {
    @autoreleasepool {
        NSLog(@"[AntiDetect & MultiOpen] Dylib loaded into %@", NSProcessInfo.processInfo.processName);

        // 1. fishhook: 重绑定 C 符号
        rebind_symbols((struct rebinding[3]){
            {"getenv",               (void *)custom_getenv,               (void **)&orig_getenv},
            {"_dyld_get_image_name", (void *)custom_dyld_get_image_name,  (void **)&orig_dyld_get_image_name},
            {"open",                 (void *)custom_open,                 (void **)&orig_open}
        }, 3);

        // 2. Method Swizzling: 劫持 NSBundle -bundleIdentifier
        Method m = class_getInstanceMethod([NSBundle class], @selector(bundleIdentifier));
        if (m != NULL) {
            orig_bundleIdentifier = (NSString *(*)(id, SEL))method_getImplementation(m);
            method_setImplementation(m, (IMP)custom_bundleIdentifier);
        } else {
            NSLog(@"[AntiDetect] WARNING: NSBundle.bundleIdentifier method not found");
        }
    }
}
