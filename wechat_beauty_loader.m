// wechat_beauty_loader.m - 让微信启动时加载微颜的美颜 bundle
// 编译: clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=12.0 -fobjc-arc -dynamiclib -framework Foundation wechat_beauty_loader.m -o wechat_beauty_loader.dylib -Wl,-install_name,@executable_path/Frameworks/wechat_beauty_loader.dylib
// codesign --force --sign - wechat_beauty_loader.dylib

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <stdio.h>

#define BUNDLE_PATH(base, name) base stringByAppendingPathComponent:name

static void loadBeautyBundles(NSString *appBundlePath) {
    NSArray *bundles = @[
        @"MYSkin.bundle", @"MYStyle.bundle", @"MYMakeup.bundle",
        @"MYShape.bundle", @"MYFilter.bundle", @"MYSticker.bundle",
        @"MYBody.bundle", @"MYHUD.bundle", @"MYImages.bundle",
        @"face_beautification.bundle", @"face_makeup.bundle"
    ];
    
    NSString *frameworksPath = BUNDLE_PATH(appBundlePath, @"Frameworks");
    
    for (NSString *bundleName in bundles) {
        NSString *bundlePath = [frameworksPath stringByAppendingPathComponent:bundleName];
        NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
        if (bundle.isLoaded) {
            fprintf(stderr, "[BEAUTY] Already loaded: %s\n", bundleName.UTF8String);
            continue;
        }
        BOOL loaded = [bundle load];
        if (loaded) {
            fprintf(stderr, "[BEAUTY] Loaded: %s\n", bundleName.UTF8String);
        } else {
            fprintf(stderr, "[BEAUTY] Failed to load: %s - %s\n", 
                    bundleName.UTF8String, 
                    bundle.loadError.localizedDescription.UTF8String);
        }
    }
}

__attribute__((constructor))
static void beauty_loader_init(void) {
    NSString *appBundlePath = [[NSBundle mainBundle] bundlePath];
    fprintf(stderr, "[BEAUTY] Loading WeChat beauty bundles from: %s\n", appBundlePath.UTF8String);
    loadBeautyBundles(appBundlePath);
    fprintf(stderr, "[BEAUTY] Beauty loader armed\n");
}
