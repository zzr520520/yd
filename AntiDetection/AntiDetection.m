#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <objc/runtime.h>
#include "fishhook.h"

// 原始函数指针
static char *(*orig_getenv)(const char *name);
static const char *(*orig_dyld_get_image_name)(uint32_t image_index);

// 需要隐藏的注入特征关键词
static const char *kHiddenKeywords[] = {
    "AntiDetection",
    "libMediaUtility",
    "YourInjectedPlugin",
    "tweak",
    "Substrate",
    NULL
};

// 1. Hook getenv：隐藏 DYLD_INSERT_LIBRARIES 环境变量
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

// 2. Hook _dyld_get_image_name：隐藏注入 dylib 的镜像路径
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

// 3. 通过 fishhook 重绑定符号
__attribute__((constructor))
static void AntiDetectionInit(void) {
    @autoreleasepool {
        NSLog(@"[AntiDetect] Loaded into %@", NSProcessInfo.processInfo.processName);

        rebind_symbols((struct rebinding[2]){
            {"getenv", (void *)custom_getenv, (void **)&orig_getenv},
            {"_dyld_get_image_name", (void *)custom_dyld_get_image_name, (void **)&orig_dyld_get_image_name}
        }, 2);
    }
}
