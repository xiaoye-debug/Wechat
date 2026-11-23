#import "WCEBHostPolicy.h"
#include <stdio.h>
#include <stdlib.h>

static void check(BOOL actual, BOOL expected, const char *name)
{
    if (actual != expected) {
        fprintf(stderr, "FAIL host policy: %s\n", name);
        exit(1);
    }
}

int main(void)
{
    @autoreleasepool {
        NSArray<NSString *> *bundleIDs = @[
            @"com.tencent.xin", @"com.tencent.wx",
            @"com.tencent.qy.xin", @"com.tencent.mm.xin"
        ];
        for (NSString *bundleID in bundleIDs) {
            check(WCEBSupportsHost(bundleID, @"DifferentMainExecutable", NO), YES, "Supported bundle accepted");
            check(WCEBSupportsHost(bundleID, @"WeChat", YES), NO, "extension excluded");
        }
        check(WCEBSupportsHost(@"custom.resigned.wechat", @"WeChat", NO), YES, "resigned WeChat");
        check(WCEBSupportsHost(@"com.tencent.xin.extension", @"Extension", NO), NO, "no prefix matching");
        check(WCEBSupportsHost(@"unrelated.app", @"DifferentApp", NO), NO, "unrelated host");
        check(WCEBSupportsHost(nil, nil, NO), NO, "missing identity");
        check(WCEBSupportsHost(nil, @"WeChat", YES), NO, "resigned extension");
        puts("PASS: 13 host policy cases");
    }
    return 0;
}
