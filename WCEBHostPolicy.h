#import <Foundation/Foundation.h>

// Exact bundle IDs from the verified package filter. No prefix wildcard.
static inline BOOL WCEBSupportsHost(NSString *bundleID, NSString *executable, BOOL isExtension)
{
    if (isExtension) return NO;
    NSArray<NSString *> *supportedBundles = @[
        @"com.tencent.xin",
        @"com.tencent.wx",
        @"com.tencent.qy.xin",
        @"com.tencent.mm.xin"
    ];
    if (bundleID && [supportedBundles containsObject:bundleID]) return YES;
    // IPA re-signers may replace CFBundleIdentifier but retain the executable.
    return [executable isEqualToString:@"WeChat"];
}
