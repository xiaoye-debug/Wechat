// 0.2.0: reviewed DD + header interfaces; each method has its own guarded Logos group.
// Static source merge. No device/runtime success is implied by these declarations.
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <os/log.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dispatch/dispatch.h>
#include <string.h>
#include <stdlib.h>

#define WCEB_DOMAIN "com.macxk.wcenvbypass"
#define WCEB_VERSION "0.2.0"

static os_log_t gLog;
static BOOL gEnabled = YES;
static BOOL gJailbreak = YES;
static BOOL gModules = YES;
static BOOL gEnvChecks = YES;
static BOOL gReporting = YES;
static BOOL gSceneGate = YES;
static BOOL gIntegrity = NO;
static BOOL gVerbose = NO;
static BOOL gSystemQueries = YES;
static BOOL gClientChecks = YES;
static BOOL gCacheReports = YES;
static BOOL gSignature = YES;
static BOOL gReportFields = NO;
static BOOL gDeviceIdentity = NO;
static BOOL gReceiptView = NO;
static BOOL gDiagnosticsSuppression = NO;
static BOOL gHeaderEnvironment = YES;
static BOOL gPaymentEnvironment = NO;

static BOOL WCEBBool(NSString *key, BOOL fallback)
{
    CFPropertyListRef property = CFPreferencesCopyAppValue((__bridge CFStringRef)key, CFSTR(WCEB_DOMAIN));
    id value = CFBridgingRelease(property);
    if ([value isKindOfClass:[NSNumber class]] || [value isKindOfClass:[NSString class]]) {
        return [value boolValue];
    }
    return fallback;
}

static void WCEBLoadConfig(void)
{
    CFPreferencesAppSynchronize(CFSTR(WCEB_DOMAIN));
    gEnabled = WCEBBool(@"Enabled", YES);
    gJailbreak = WCEBBool(@"HookJailbreak", YES);
    gModules = WCEBBool(@"HookModules", YES);
    gEnvChecks = WCEBBool(@"HookEnvChecks", YES);
    gReporting = WCEBBool(@"HookReporting", YES);
    gSceneGate = WCEBBool(@"HookSceneGate", YES);
    gIntegrity = WCEBBool(@"HookIntegrity", NO);
    gVerbose = WCEBBool(@"LogEnabled", NO);
    gSystemQueries = WCEBBool(@"HookSystemQueries", YES);
    gClientChecks = WCEBBool(@"HookClientChecks", YES);
    gCacheReports = WCEBBool(@"HookCacheReports", YES);
    gSignature = WCEBBool(@"HookSignature", YES);
    gReportFields = WCEBBool(@"HookReportFields", NO);
    gDeviceIdentity = WCEBBool(@"HookDeviceIdentity", NO);
    gReceiptView = WCEBBool(@"HookReceiptView", NO);
    gDiagnosticsSuppression = WCEBBool(@"HookDiagnosticsSuppression", NO);
    gHeaderEnvironment = WCEBBool(@"HookHeaderEnvironment", YES);
    gPaymentEnvironment = WCEBBool(@"HookPaymentEnvironment", NO);
}

#define WCEBLog(fmt, ...) \
    do { if (gVerbose && gLog) os_log_info(gLog, "[WCEB] " fmt, ##__VA_ARGS__); } while (0)

#pragma mark - Runtime method contract

typedef struct {
    const char *className;
    const char *selector;
    BOOL classMethod;
    const char *returnType;
    unsigned int argumentCount;
    const char *arguments[8];
} WCEBHookSpec;

static const char *WCEBSkipQualifiers(const char *type)
{
    if (!type) return "";
    while (*type && strchr("rnNoORV", *type)) ++type;
    return type;
}

static BOOL WCEBTypesMatch(const char *expected, const char *actual)
{
    expected = WCEBSkipQualifiers(expected);
    actual = WCEBSkipQualifiers(actual);
    // Pointee qualifiers and typed-object names may differ in SDK metadata.
    // Recurse rather than treating every pointer as interchangeable.
    if (*expected == '^' && *actual == '^') return WCEBTypesMatch(expected + 1, actual + 1);
    // Typed objects and id share the object ABI. A class-dumped unknown block
    // is object-compatible here, without claiming its full block prototype.
    if (*expected == '@' && *actual == '@') return YES;
    return strcmp(expected, actual) == 0;
}

static Method WCEBLookup(const WCEBHookSpec *spec)
{
    Class cls = objc_getClass(spec->className);
    if (!cls) return NULL;
    SEL selector = sel_registerName(spec->selector);
    return spec->classMethod ? class_getClassMethod(cls, selector) : class_getInstanceMethod(cls, selector);
}

static BOOL WCEBPrepare(const WCEBHookSpec *spec, IMP *previous)
{
    Method method = WCEBLookup(spec);
    if (!method) {
        WCEBLog("skip missing %s %s", spec->className, spec->selector);
        return NO;
    }
    if (method_getNumberOfArguments(method) != spec->argumentCount + 2) {
        WCEBLog("skip argument count %s %s", spec->className, spec->selector);
        return NO;
    }
    char *actual = method_copyReturnType(method);
    BOOL compatible = WCEBTypesMatch(spec->returnType, actual);
    free(actual);
    for (unsigned int index = 0; compatible && index < spec->argumentCount; ++index) {
        actual = method_copyArgumentType(method, index + 2);
        compatible = WCEBTypesMatch(spec->arguments[index], actual);
        free(actual);
    }
    if (!compatible) {
        WCEBLog("skip incompatible ABI %s %s", spec->className, spec->selector);
        return NO;
    }
    *previous = method_getImplementation(method);
    return YES;
}

static BOOL WCEBRecordInstall(const WCEBHookSpec *spec, IMP previous)
{
    Method method = WCEBLookup(spec);
    BOOL changed = method && method_getImplementation(method) != previous;
    WCEBLog("%s %s %s", changed ? "installed" : "unchanged", spec->className, spec->selector);
    return changed;
}

#pragma mark - DD system queries (arm64 0x47f8-0x4ee8, 0x534c)

// DD predicate 0x5858. Prefix entries come from __DATA_CONST 0x8100;
// substring entries come from 0x8178. Preserve its case-sensitive matching.
static BOOL WCEBDDIsHiddenPath(id candidate)
{
    if (![candidate isKindOfClass:[NSString class]]) return NO;
    const char *path = [(NSString *)candidate UTF8String];
    if (!path || !*path) return NO;

    static const char * const prefixes[] = {
        "/bin/bash", "/bin/sh", "/etc/apt", "/private/var/lib/apt",
        "/usr/sbin/sshd", "/usr/libexec/ssh-keysign", "/Library/MobileSubstrate",
        "/Applications/Cydia.app", "/Tweak", "/tweak", "/dopamine",
        "/MobileSubstrate", "/var/jb", "/private/var/jb"
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i) {
        size_t length = strlen(prefixes[i]);
        if (strncmp(path, prefixes[i], length) == 0 &&
            (path[length] == '\0' || path[length] == '/')) return YES;
    }
    static const char * const keywords[] = {
        "MobileSubstrate", "Cydia", "cydia", "TweakInject", "libellekit",
        "libhooker", "libsubstitute", "libsubstrate", "dopamine", "Dopamine",
        "palera1n", "serotonin", "roothide", "jbroot", "TrollStore",
        "Sileo", "Zebra", "Filza", "Frida", "frida", "DDAntiBan"
    };
    for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); ++i) {
        if (strstr(path, keywords[i])) return YES;
    }
    return NO;
}

// DD 0x5654 retains nonmatching strings and all non-string array members.
// A caller with an unexpected return type keeps its original object.
static id WCEBDDFilterStrings(id values)
{
    if (![values isKindOfClass:[NSArray class]]) return values;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:[values count]];
    for (id value in values) {
        if (!WCEBDDIsHiddenPath(value)) [filtered addObject:value];
    }
    return [filtered copy];
}

// DD helper 0x5994: hide embedded.mobileprovision inside application bundles.
static BOOL WCEBDDIsProvisioningPath(id candidate)
{
    if (![candidate isKindOfClass:[NSString class]]) return NO;
    NSString *path = candidate;
    if (![path.lastPathComponent isEqualToString:@"embedded.mobileprovision"]) return NO;
    if ([path rangeOfString:@".app/"].location != NSNotFound) return YES;
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    return bundle.length > 0 &&
        ([path isEqualToString:bundle] || [path hasPrefix:[bundle stringByAppendingString:@"/"]]);
}

static void WCEBDDSetMissingFileError(NSError **error, NSString *path)
{
    if (!error) return;
    *error = [NSError errorWithDomain:NSCocoaErrorDomain
                                code:NSFileReadNoSuchFileError
                            userInfo:path ? @{NSFilePathErrorKey: path} : nil];
}

static NSString *WCEBDDPreferenceString(CFStringRef key)
{
    CFPropertyListRef property = CFPreferencesCopyAppValue(key, CFSTR(WCEB_DOMAIN));
    id value = CFBridgingRelease(property);
    return [value isKindOfClass:[NSString class]] ? value : nil;
}

// Optional compatibility with DD's IDFV view. Only this tweak's domain is written.
// Valid UUIDs are cached once per process; malformed configured strings fall back.
static NSUUID *WCEBDDVendorIdentifier(void)
{
    static NSUUID *identifier;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        const char *environmentValue = getenv("ddab_fake_idfv");
        NSString *configured = environmentValue ? [NSString stringWithUTF8String:environmentValue] : nil;
        if (configured.length > 0) identifier = [[NSUUID alloc] initWithUUIDString:configured];
        if (!identifier) {
            configured = WCEBDDPreferenceString(CFSTR("FakeIDFV"));
            if (configured.length > 0) identifier = [[NSUUID alloc] initWithUUIDString:configured];
        }
        if (!identifier) {
            configured = WCEBDDPreferenceString(CFSTR("GeneratedIDFV"));
            if (configured.length > 0) identifier = [[NSUUID alloc] initWithUUIDString:configured];
        }
        if (!identifier) {
            identifier = [NSUUID UUID];
            CFPreferencesSetAppValue(CFSTR("GeneratedIDFV"),
                                     (__bridge CFStringRef)identifier.UUIDString,
                                     CFSTR(WCEB_DOMAIN));
            CFPreferencesAppSynchronize(CFSTR(WCEB_DOMAIN));
        }
    });
    return identifier;
}


%group WCEBHook001
%hook NSProcessInfo
- (NSDictionary *)environment
{
    NSDictionary *original = %orig;
    if (!gEnabled || !gSystemQueries || ![original isKindOfClass:[NSDictionary class]]) return original;
    NSMutableDictionary *filtered = [original mutableCopy];
    [filtered removeObjectForKey:@"DYLD_INSERT_LIBRARIES"];
    return [filtered copy];
}
%end
%end



%group WCEBHook002
%hook NSFileManager
- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error
{
    NSArray *original = %orig;
    if (!gEnabled || !gSystemQueries) return original;
    // Preserve original failures and error out-parameters unchanged.
    return WCEBDDFilterStrings(original);
}
%end
%end

%group WCEBHook003
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path
{
    if (gEnabled && gSystemQueries && WCEBDDIsHiddenPath(path)) return NO;
    return %orig;
}
%end
%end

%group WCEBHook004
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory
{
    if (gEnabled && gSystemQueries && WCEBDDIsHiddenPath(path)) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}
%end
%end

%group WCEBHook005
%hook NSFileManager
- (NSData *)contentsAtPath:(NSString *)path
{
    if (gEnabled && gSystemQueries && WCEBDDIsHiddenPath(path)) return nil;
    return %orig;
}
%end
%end

%group WCEBHook006
%hook NSFileManager
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error
{
    if (gEnabled && gSystemQueries && WCEBDDIsHiddenPath(path)) {
        WCEBDDSetMissingFileError(error, path);
        return nil;
    }
    return %orig;
}
%end
%end



%group WCEBHook007
%hook NSBundle
- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)extension
{
    if (gEnabled && gSystemQueries && name.length > 0 &&
        ([name.lastPathComponent isEqualToString:@"embedded.mobileprovision"] ||
         [extension isEqualToString:@"mobileprovision"])) return nil;
    return %orig;
}
%end
%end

%group WCEBHook008
%hook NSBundle
- (NSURL *)appStoreReceiptURL
{
    if (!gEnabled || !gReceiptView) return %orig;
    NSString *library = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES).firstObject;
    if (!library.length) return %orig;
    // A URL view only: no receipt is created or declared authentic.
    return [NSURL fileURLWithPath:[library stringByAppendingPathComponent:@"StoreKit/receipt"]];
}
%end
%end



%group WCEBHook009
%hook NSString
+ (id)stringWithContentsOfFile:(NSString *)path encoding:(NSStringEncoding)encoding error:(NSError **)error
{
    if (gEnabled && gSystemQueries &&
        (WCEBDDIsProvisioningPath(path) || WCEBDDIsHiddenPath(path))) {
        WCEBDDSetMissingFileError(error, path);
        return nil;
    }
    return %orig;
}
%end
%end



%group WCEBHook010
%hook NSDictionary
+ (id)dictionaryWithContentsOfFile:(NSString *)path
{
    if (gEnabled && gSystemQueries &&
        (WCEBDDIsProvisioningPath(path) || WCEBDDIsHiddenPath(path))) return nil;
    return %orig;
}
%end
%end



%group WCEBHook011
%hook UIDevice
- (NSUUID *)identifierForVendor
{
    if (!gEnabled || !gDeviceIdentity) return %orig;
    return WCEBDDVendorIdentifier();
}
%end
%end



%group WCEBHook012
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url
{
    if (gEnabled && gSystemQueries) {
        const char *scheme = [url.scheme UTF8String];
        static const char * const schemes[] = {"cydia", "electra", "dopamine", "sileo", "zebra", "filza"};
        if (scheme) {
            for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); ++i) {
                if (strcmp(scheme, schemes[i]) == 0) return NO;
            }
        }
    }
    return %orig;
}
%end
%end


static BOOL WCEBIsSuspiciousPath(NSString *path)
{
    return WCEBDDIsHiddenPath(path);
}

#pragma mark - 1. SecModuleManager（总闸）


%group WCEBHook013
%hook SecModuleManager
+ (_Bool)isSceneEnable:(id)scene
{
    if (!gEnabled || !gSceneGate) return %orig;
    WCEBLog("isSceneEnable -> NO");
    return NO;
}
%end
%end

%group WCEBHook014
%hook SecModuleManager
+ (id)getSecInfo:(id)a
{
    if (!gEnabled || !gSceneGate) return %orig;
    WCEBLog("getSecInfo -> nil");
    return nil;
}
%end
%end

%group WCEBHook015
%hook SecModuleManager
+ (id)getSecExtendInfoWithScene:(id)a
{
    if (!gEnabled || !gSceneGate) return %orig;
    return nil;
}
%end
%end

%group WCEBHook016
%hook SecModuleManager
+ (void)doGetSecInfo
{
    if (!gEnabled || !gSceneGate) return %orig;
    WCEBLog("doGetSecInfo skipped");
}
%end
%end

%group WCEBHook017
%hook SecModuleManager
+ (void)setIsAlreadyGet:(_Bool)v
{
    if (!gEnabled || !gSceneGate) return %orig;
    WCEBLog("setIsAlreadyGet:%d ignored", v);
}
%end
%end

%group WCEBHook018
%hook SecModuleManager
+ (_Bool)isAlreadyGet
{
    if (!gEnabled || !gSceneGate) return %orig;
    return YES;
}
%end
%end

%group WCEBHook019
%hook SecModuleManager
+ (id)getSuspiciousProcessModules
{
    if (!gEnabled || !gModules) return %orig;
    WCEBLog("getSuspiciousProcessModules -> []");
    return @[];
}
%end
%end

%group WCEBHook020
%hook SecModuleManager
+ (id)getSuspiciousProcessModulesByDyld
{
    if (!gEnabled || !gModules) return %orig;
    WCEBLog("getSuspiciousProcessModulesByDyld -> []");
    return @[];
}
%end
%end

%group WCEBHook021
%hook SecModuleManager
+ (int)getSupiciousModulesBySyscallWithProtection:(char (*)[256])buf maxCount:(int)max
{
    if (!gEnabled || !gModules) return %orig;
    WCEBLog("getSupiciousModulesBySyscall -> 0");
    return 0;
}
%end
%end

%group WCEBHook022
%hook SecModuleManager
+ (id)getJailbreakSuspiciousModules
{
    if (!gEnabled || !gModules) return %orig;
    return @[];
}
%end
%end

%group WCEBHook023
%hook SecModuleManager
+ (id)suspiciousModules
{
    if (!gEnabled || !gModules) return %orig;
    return @[];
}
%end
%end

%group WCEBHook024
%hook SecModuleManager
+ (void)setSuspiciousModules:(id)v
{
    if (!gEnabled || !gModules) return %orig;
    WCEBLog("setSuspiciousModules ignored");
}
%end
%end

%group WCEBHook025
%hook SecModuleManager
+ (id)jailbreakModules
{
    if (!gEnabled || !gJailbreak) return %orig;
    return @[];
}
%end
%end

%group WCEBHook026
%hook SecModuleManager
+ (void)setJailbreakModules:(id)v
{
    if (!gEnabled || !gJailbreak) return %orig;
}
%end
%end

%group WCEBHook027
%hook SecModuleManager
+ (id)jailbreakPaths
{
    if (!gEnabled || !gJailbreak) return %orig;
    return @[];
}
%end
%end

%group WCEBHook028
%hook SecModuleManager
+ (id)suspiciousPathKeywords
{
    if (!gEnabled || !gModules) return %orig;
    return @[];
}
%end
%end


#pragma mark - 2. JailBreakHelper（越狱）


%group WCEBHook029
%hook JailBreakHelper
+ (_Bool)JailBroken
{
    if (!gEnabled || !gJailbreak) return %orig;
    WCEBLog("JailBroken -> NO");
    return NO;
}
%end
%end

%group WCEBHook030
%hook JailBreakHelper
- (_Bool)IsJailBreak
{
    if (!gEnabled || !gJailbreak) return %orig;
    WCEBLog("IsJailBreak -> NO");
    return NO;
}
%end
%end

%group WCEBHook031
%hook JailBreakHelper
- (_Bool)HasInstallJailbreakPlugin:(id)plugin
{
    if (!gEnabled || !gJailbreak) return %orig;
    WCEBLog("HasInstallJailbreakPlugin -> NO");
    return NO;
}
%end
%end

%group WCEBHook032
%hook JailBreakHelper
+ (id)getJailbreakPath
{
    if (!gEnabled || !gJailbreak) return %orig;
    return nil;
}
%end
%end

%group WCEBHook033
%hook JailBreakHelper
+ (id)getJailbreakRootDir
{
    if (!gEnabled || !gJailbreak) return %orig;
    return nil;
}
%end
%end

%group WCEBHook034
%hook JailBreakHelper
+ (id)getIAPCheckPath
{
    if (!gEnabled || !gJailbreak) return %orig;
    return nil;
}
%end
%end

%group WCEBHook035
%hook JailBreakHelper
- (_Bool)isOverADay
{
    if (!gEnabled || !gJailbreak) return %orig;
    return NO;
}
%end
%end

%group WCEBHook036
%hook JailBreakHelper
- (_Bool)save
{
    if (!gEnabled || !gJailbreak) return %orig;
    return YES;
}
%end
%end


#pragma mark - 3. SecDataReportUtil（环境探测 + 上报）


%group WCEBHook037
%hook SecDataReportUtil
+ (_Bool)checkScreenRecording
{
    if (!gEnabled || !gEnvChecks) return %orig;
    WCEBLog("checkScreenRecording -> NO");
    return NO;
}
%end
%end

%group WCEBHook038
%hook SecDataReportUtil
+ (_Bool)checkVpnConnect
{
    if (!gEnabled || !gEnvChecks) return %orig;
    WCEBLog("checkVpnConnect -> NO");
    return NO;
}
%end
%end

%group WCEBHook039
%hook SecDataReportUtil
+ (_Bool)checkVoipCalling
{
    if (!gEnabled || !gEnvChecks) return %orig;
    WCEBLog("checkVoipCalling -> NO");
    return NO;
}
%end
%end

%group WCEBHook040
%hook SecDataReportUtil
- (void)doReportInfo:(id)info eventName:(id)name
{
    if (!gEnabled || !gReporting) return %orig;
    WCEBLog("SecDataReportUtil report skipped");
}
%end
%end


#pragma mark - 4. 设备 / 调试器


%group WCEBHook041
%hook DeviceInfo
+ (_Bool)isInSimulator
{
    if (!gEnabled || !gEnvChecks) return %orig;
    return NO;
}
%end
%end



%group WCEBHook042
%hook JSCDebugger
+ (_Bool)isSupportedDebugger
{
    if (!gEnabled || !gEnvChecks) return %orig;
    return NO;
}
%end
%end


#pragma mark - 5. 消息风控上报


%group WCEBHook043
%hook MessageSecReporter
+ (void)reportMessage:(id)msg action:(unsigned int)action
{
    if (!gEnabled || !gReporting) return %orig;
    WCEBLog("MessageSecReporter blocked action=%u", action);
}
%end
%end


#pragma mark - 6. 文件完整性（默认关）


%group WCEBHook044
%hook MMLiveCommonUtil
+ (unsigned long long)validateFilesIntegrityInDirectory:(id)dir withManifest:(id)manifest
{
    if (!gEnabled || !gIntegrity) return %orig;
    WCEBLog("validateFilesIntegrity -> 0");
    return 0;
}
%end
%end

%group WCEBHook045
%hook MMLiveCommonUtil
+ (unsigned long long)validateFilesIntegrityInDirectory:(id)dir withManifest:(id)manifest forEachFileAction:(id)action
{
    if (!gEnabled || !gIntegrity) return %orig;
    return 0;
}
%end
%end


#import <objc/message.h>

#pragma mark - DD 微信内部检查与头文件新增入口

// 仅对数组中的字符串做路径过滤；未知返回类型保持原样。
static id WCEBAppFilterImages(id value)
{
    if (!value) return @[];
    if (![value isKindOfClass:[NSArray class]]) return value;
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:[value count]];
    for (id item in value) {
        if (![item isKindOfClass:[NSString class]] || !WCEBIsSuspiciousPath(item)) {
            [result addObject:item];
        }
    }
    return [result copy];
}

// DD 0x5b94：执行原 getter 后，按原返回对象类型给出空值。
static id WCEBAppEmptyField(id value)
{
    if ([value isKindOfClass:[NSString class]]) return @"";
    if ([value isKindOfClass:[NSData class]]) return [NSData data];
    return nil;
}

static BOOL WCEBAppCanInvokeBooleanClassMethod(Class cls, SEL selector)
{
    Method method = class_getClassMethod(cls, selector);
    if (!method || method_getNumberOfArguments(method) != 2) return NO;
    char returnType[8] = {0};
    method_getReturnType(method, returnType, sizeof(returnType));
    return returnType[0] == 'B' && returnType[1] == '\0';
}


%group WCEBHook046
%hook CUtility
+ (_Bool)isBeingDebugged
{
    if (!gEnabled || !gEnvChecks) return %orig;
    return NO;
}
%end
%end



%group WCEBHook047
%hook MatrixDeviceInfo
+ (_Bool)isBeingDebugged
{
    if (!gEnabled || !gEnvChecks) return %orig;
    return NO;
}
%end
%end



%group WCEBHook048
%hook ClientCheckMgr
- (id)getImageList
{
    if (!gEnabled || !gClientChecks) return %orig;
    return WCEBAppFilterImages(%orig);
}
%end
%end

%group WCEBHook049
%hook ClientCheckMgr
- (id)runningProcesses
{
    if (!gEnabled || !gClientChecks) return %orig;
    return @[];
}
%end
%end

%group WCEBHook050
%hook ClientCheckMgr
- (void)checkHook:(id)request
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook051
%hook ClientCheckMgr
- (void)checkHookWithSeq:(unsigned int)seq
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook052
%hook ClientCheckMgr
- (void)checkConsistency:(id)request
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook053
%hook ClientCheckMgr
- (void)registerAddImageCallBack
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook054
%hook ClientCheckMgr
- (void)OnGetNewXmlMsg:(id)message Type:(id)type MsgWrap:(id)wrap
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook055
%hook ClientCheckMgr
- (void)onAuthOK
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook056
%hook ClientCheckMgr
- (void)test
{
    if (!gEnabled || !gClientChecks) return %orig;
}
%end
%end

%group WCEBHook057
%hook ClientCheckMgr
- (void)reportAppList:(id)request
{
    if (!gEnabled || !gClientChecks || !gReporting) return %orig;
}
%end
%end

%group WCEBHook058
%hook ClientCheckMgr
- (void)reportFileConsistency:(id)request fileName:(id)fileName offset:(unsigned int)offset bufferSize:(unsigned int)bufferSize seq:(unsigned int)seq
{
    if (!gEnabled || !gClientChecks || !gReporting) return %orig;
}
%end
%end



%group WCEBHook059
%hook MMClientCacheManager
- (void)reportExtInfo:(id)info
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end

%group WCEBHook060
%hook MMClientCacheManager
- (void)doDReport
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end

%group WCEBHook061
%hook MMClientCacheManager
- (void)doSSReport:(unsigned int)type
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end

%group WCEBHook062
%hook MMClientCacheManager
- (void)doSSReport:(unsigned int)type isBasic:(_Bool)isBasic
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end

%group WCEBHook063
%hook MMClientCacheManager
- (void)onAuthOK
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end

%group WCEBHook064
%hook MMClientCacheManager
- (void)onServiceEnterBackground
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end

%group WCEBHook065
%hook MMClientCacheManager
- (void)doSSReportForPayCheckoutCounter
{
    if (!gEnabled || !gReporting || !gCacheReports) return %orig;
}
%end
%end



%group WCEBHook066
%hook CAppUtil
+ (_Bool)isProductionSignature
{
    if (!gEnabled || !gSignature) return %orig;
    return YES;
}
%end
%end



%group WCEBHook067
%hook KindaDeviceService
- (_Bool)isRoot
{
    if (!gEnabled || !gJailbreak) return %orig;
    return NO;
}
%end
%end


// DD 字段修改为独立开关，默认不影响正常业务数据。

%group WCEBHook068
%hook WCExtInfo
- (void)setCcData:(id)value
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
}
%end
%end

%group WCEBHook069
%hook WCExtInfo
- (void)setBehaviorId:(id)value
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
}
%end
%end

%group WCEBHook070
%hook WCExtInfo
- (void)setUserAttrInfo:(id)value
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
}
%end
%end



%group WCEBHook071
%hook NormalContactVerifyLogic
- (id)m_reportInfo
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
    return WCEBAppEmptyField(%orig);
}
%end
%end



%group WCEBHook072
%hook CContactVerifyLogic
- (id)m_reportInfo
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
    return WCEBAppEmptyField(%orig);
}
%end
%end

%group WCEBHook073
%hook CContactVerifyLogic
- (id)m_spamContext
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
    return WCEBAppEmptyField(%orig);
}
%end
%end



%group WCEBHook074
%hook SendVerifyMsgLogicController
- (id)m_spamContext
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
    return WCEBAppEmptyField(%orig);
}
%end
%end



%group WCEBHook075
%hook CVerifyContactWrap
- (id)m_reportInfo
{
    if (!gEnabled || !gReporting || !gReportFields) return %orig;
    return WCEBAppEmptyField(%orig);
}
%end
%end


// DD 诊断路径单独控制，默认保留崩溃记录和恢复功能。

%group WCEBHook076
%hook WCCrashBlockMonitorPlugin
- (_Bool)start
{
    if (!gEnabled || !gDiagnosticsSuppression) return %orig;
    return YES;
}
%end
%end



%group WCEBHook077
%hook KSCrash
- (_Bool)install
{
    if (!gEnabled || !gDiagnosticsSuppression) return %orig;
    return YES;
}
%end
%end

%group WCEBHook078
%hook KSCrash
- (void)setMonitoring:(int)monitoring
{
    if (!gEnabled || !gDiagnosticsSuppression) return %orig;
}
%end
%end



%group WCEBHook079
%hook MMSafeModeMgr
- (_Bool)shouldEnterSafeMode
{
    if (!gEnabled || !gDiagnosticsSuppression) return %orig;
    return NO;
}
%end
%end


// WCAccountControlMgr -onAuthOK 在 DD 中仅转调原实现，不安装无行为变化的 Hook。


%group WCEBHook080
%hook TSEnvironment
+ (int)rootFlag
{
    if (!gEnabled || !gHeaderEnvironment || !gJailbreak) return %orig;
    return 0;
}
%end
%end

%group WCEBHook081
%hook TSEnvironment
+ (id)loadedImageNames
{
    if (!gEnabled || !gHeaderEnvironment || !gModules) return %orig;
    return WCEBAppFilterImages(%orig);
}
%end
%end

%group WCEBHook082
%hook TSEnvironment
+ (_Bool)isBeingDebugged
{
    if (!gEnabled || !gHeaderEnvironment || !gEnvChecks) return %orig;
    return NO;
}
%end
%end


// 支付环境为默认关闭的实验组。组合能力方法保留硬件/录入能力判断。

%group WCEBHook083
%hook WCPayTouchIDAuthHelper
+ (_Bool)isDeviceJailBreak
{
    if (!gEnabled || !gPaymentEnvironment) return %orig;
    return NO;
}
%end
%end

%group WCEBHook084
%hook WCPayTouchIDAuthHelper
+ (_Bool)isDeviceTouchIDAvailableAndNotJailBreak
{
    if (!gEnabled || !gPaymentEnvironment) return %orig;
    SEL capability = @selector(isDeviceTouchIDAvailable);
    if (!WCEBAppCanInvokeBooleanClassMethod((Class)self, capability)) return %orig;
    return ((_Bool (*)(id, SEL))objc_msgSend)((id)self, capability);
}
%end
%end

%group WCEBHook085
%hook WCPayTouchIDAuthHelper
+ (_Bool)isDeviceTouchIDHardwareSupportedAndNotJailBreak
{
    if (!gEnabled || !gPaymentEnvironment) return %orig;
    SEL capability = @selector(isDeviceTouchIDHardwareSupported);
    if (!WCEBAppCanInvokeBooleanClassMethod((Class)self, capability)) return %orig;
    return ((_Bool (*)(id, SEL))objc_msgSend)((id)self, capability);
}
%end
%end



%group WCEBHook086
%hook iAPMgr
- (_Bool)cannotPurchaseDuetoJailbreakPlugin:(_Bool)checkPlugin
{
    if (!gEnabled || !gPaymentEnvironment) return %orig;
    return NO;
}
%end
%end

%group WCEBHook087
%hook iAPMgr
- (long long)RestoreCompletedTransactionsNeedCheckJailBreak:(_Bool)needCheck
{
    if (!gEnabled || !gPaymentEnvironment) return %orig;
    return %orig(NO);
}
%end
%end

%group WCEBHook088
%hook iAPMgr
- (long long)Purchase:(id)product extInfo:(id)extInfo NeedCheckJailBreak:(_Bool)needCheck
{
    if (!gEnabled || !gPaymentEnvironment) return %orig;
    return %orig(product, extInfo, NO);
}
%end
%end


#pragma mark - Expected method signatures (one row per guarded group)

static const WCEBHookSpec kHookSpecs[] = {
    {"NSProcessInfo", "environment", NO, @encode(NSDictionary *), 0, {NULL}},
    {"NSFileManager", "contentsOfDirectoryAtPath:error:", NO, @encode(NSArray *), 2, {@encode(NSString *), @encode(NSError * __autoreleasing *)}},
    {"NSFileManager", "fileExistsAtPath:", NO, @encode(BOOL), 1, {@encode(NSString *)}},
    {"NSFileManager", "fileExistsAtPath:isDirectory:", NO, @encode(BOOL), 2, {@encode(NSString *), @encode(BOOL *)}},
    {"NSFileManager", "contentsAtPath:", NO, @encode(NSData *), 1, {@encode(NSString *)}},
    {"NSFileManager", "attributesOfItemAtPath:error:", NO, @encode(NSDictionary *), 2, {@encode(NSString *), @encode(NSError * __autoreleasing *)}},
    {"NSBundle", "pathForResource:ofType:", NO, @encode(NSString *), 2, {@encode(NSString *), @encode(NSString *)}},
    {"NSBundle", "appStoreReceiptURL", NO, @encode(NSURL *), 0, {NULL}},
    {"NSString", "stringWithContentsOfFile:encoding:error:", YES, @encode(id), 3, {@encode(NSString *), @encode(NSStringEncoding), @encode(NSError * __autoreleasing *)}},
    {"NSDictionary", "dictionaryWithContentsOfFile:", YES, @encode(id), 1, {@encode(NSString *)}},
    {"UIDevice", "identifierForVendor", NO, @encode(NSUUID *), 0, {NULL}},
    {"UIApplication", "canOpenURL:", NO, @encode(BOOL), 1, {@encode(NSURL *)}},
    {"SecModuleManager", "isSceneEnable:", YES, @encode(_Bool), 1, {@encode(id)}},
    {"SecModuleManager", "getSecInfo:", YES, @encode(id), 1, {@encode(id)}},
    {"SecModuleManager", "getSecExtendInfoWithScene:", YES, @encode(id), 1, {@encode(id)}},
    {"SecModuleManager", "doGetSecInfo", YES, @encode(void), 0, {NULL}},
    {"SecModuleManager", "setIsAlreadyGet:", YES, @encode(void), 1, {@encode(_Bool)}},
    {"SecModuleManager", "isAlreadyGet", YES, @encode(_Bool), 0, {NULL}},
    {"SecModuleManager", "getSuspiciousProcessModules", YES, @encode(id), 0, {NULL}},
    {"SecModuleManager", "getSuspiciousProcessModulesByDyld", YES, @encode(id), 0, {NULL}},
    {"SecModuleManager", "getSupiciousModulesBySyscallWithProtection:maxCount:", YES, @encode(int), 2, {@encode(char (*)[256]), @encode(int)}},
    {"SecModuleManager", "getJailbreakSuspiciousModules", YES, @encode(id), 0, {NULL}},
    {"SecModuleManager", "suspiciousModules", YES, @encode(id), 0, {NULL}},
    {"SecModuleManager", "setSuspiciousModules:", YES, @encode(void), 1, {@encode(id)}},
    {"SecModuleManager", "jailbreakModules", YES, @encode(id), 0, {NULL}},
    {"SecModuleManager", "setJailbreakModules:", YES, @encode(void), 1, {@encode(id)}},
    {"SecModuleManager", "jailbreakPaths", YES, @encode(id), 0, {NULL}},
    {"SecModuleManager", "suspiciousPathKeywords", YES, @encode(id), 0, {NULL}},
    {"JailBreakHelper", "JailBroken", YES, @encode(_Bool), 0, {NULL}},
    {"JailBreakHelper", "IsJailBreak", NO, @encode(_Bool), 0, {NULL}},
    {"JailBreakHelper", "HasInstallJailbreakPlugin:", NO, @encode(_Bool), 1, {@encode(id)}},
    {"JailBreakHelper", "getJailbreakPath", YES, @encode(id), 0, {NULL}},
    {"JailBreakHelper", "getJailbreakRootDir", YES, @encode(id), 0, {NULL}},
    {"JailBreakHelper", "getIAPCheckPath", YES, @encode(id), 0, {NULL}},
    {"JailBreakHelper", "isOverADay", NO, @encode(_Bool), 0, {NULL}},
    {"JailBreakHelper", "save", NO, @encode(_Bool), 0, {NULL}},
    {"SecDataReportUtil", "checkScreenRecording", YES, @encode(_Bool), 0, {NULL}},
    {"SecDataReportUtil", "checkVpnConnect", YES, @encode(_Bool), 0, {NULL}},
    {"SecDataReportUtil", "checkVoipCalling", YES, @encode(_Bool), 0, {NULL}},
    {"SecDataReportUtil", "doReportInfo:eventName:", NO, @encode(void), 2, {@encode(id), @encode(id)}},
    {"DeviceInfo", "isInSimulator", YES, @encode(_Bool), 0, {NULL}},
    {"JSCDebugger", "isSupportedDebugger", YES, @encode(_Bool), 0, {NULL}},
    {"MessageSecReporter", "reportMessage:action:", YES, @encode(void), 2, {@encode(id), @encode(unsigned int)}},
    {"MMLiveCommonUtil", "validateFilesIntegrityInDirectory:withManifest:", YES, @encode(unsigned long long), 2, {@encode(id), @encode(id)}},
    {"MMLiveCommonUtil", "validateFilesIntegrityInDirectory:withManifest:forEachFileAction:", YES, @encode(unsigned long long), 3, {@encode(id), @encode(id), @encode(id)}},
    {"CUtility", "isBeingDebugged", YES, @encode(_Bool), 0, {NULL}},
    {"MatrixDeviceInfo", "isBeingDebugged", YES, @encode(_Bool), 0, {NULL}},
    {"ClientCheckMgr", "getImageList", NO, @encode(id), 0, {NULL}},
    {"ClientCheckMgr", "runningProcesses", NO, @encode(id), 0, {NULL}},
    {"ClientCheckMgr", "checkHook:", NO, @encode(void), 1, {@encode(id)}},
    {"ClientCheckMgr", "checkHookWithSeq:", NO, @encode(void), 1, {@encode(unsigned int)}},
    {"ClientCheckMgr", "checkConsistency:", NO, @encode(void), 1, {@encode(id)}},
    {"ClientCheckMgr", "registerAddImageCallBack", NO, @encode(void), 0, {NULL}},
    {"ClientCheckMgr", "OnGetNewXmlMsg:Type:MsgWrap:", NO, @encode(void), 3, {@encode(id), @encode(id), @encode(id)}},
    {"ClientCheckMgr", "onAuthOK", NO, @encode(void), 0, {NULL}},
    {"ClientCheckMgr", "test", NO, @encode(void), 0, {NULL}},
    {"ClientCheckMgr", "reportAppList:", NO, @encode(void), 1, {@encode(id)}},
    {"ClientCheckMgr", "reportFileConsistency:fileName:offset:bufferSize:seq:", NO, @encode(void), 5, {@encode(id), @encode(id), @encode(unsigned int), @encode(unsigned int), @encode(unsigned int)}},
    {"MMClientCacheManager", "reportExtInfo:", NO, @encode(void), 1, {@encode(id)}},
    {"MMClientCacheManager", "doDReport", NO, @encode(void), 0, {NULL}},
    {"MMClientCacheManager", "doSSReport:", NO, @encode(void), 1, {@encode(unsigned int)}},
    {"MMClientCacheManager", "doSSReport:isBasic:", NO, @encode(void), 2, {@encode(unsigned int), @encode(_Bool)}},
    {"MMClientCacheManager", "onAuthOK", NO, @encode(void), 0, {NULL}},
    {"MMClientCacheManager", "onServiceEnterBackground", NO, @encode(void), 0, {NULL}},
    {"MMClientCacheManager", "doSSReportForPayCheckoutCounter", NO, @encode(void), 0, {NULL}},
    {"CAppUtil", "isProductionSignature", YES, @encode(_Bool), 0, {NULL}},
    {"KindaDeviceService", "isRoot", NO, @encode(_Bool), 0, {NULL}},
    {"WCExtInfo", "setCcData:", NO, @encode(void), 1, {@encode(id)}},
    {"WCExtInfo", "setBehaviorId:", NO, @encode(void), 1, {@encode(id)}},
    {"WCExtInfo", "setUserAttrInfo:", NO, @encode(void), 1, {@encode(id)}},
    {"NormalContactVerifyLogic", "m_reportInfo", NO, @encode(id), 0, {NULL}},
    {"CContactVerifyLogic", "m_reportInfo", NO, @encode(id), 0, {NULL}},
    {"CContactVerifyLogic", "m_spamContext", NO, @encode(id), 0, {NULL}},
    {"SendVerifyMsgLogicController", "m_spamContext", NO, @encode(id), 0, {NULL}},
    {"CVerifyContactWrap", "m_reportInfo", NO, @encode(id), 0, {NULL}},
    {"WCCrashBlockMonitorPlugin", "start", NO, @encode(_Bool), 0, {NULL}},
    {"KSCrash", "install", NO, @encode(_Bool), 0, {NULL}},
    {"KSCrash", "setMonitoring:", NO, @encode(void), 1, {@encode(int)}},
    {"MMSafeModeMgr", "shouldEnterSafeMode", NO, @encode(_Bool), 0, {NULL}},
    {"TSEnvironment", "rootFlag", YES, @encode(int), 0, {NULL}},
    {"TSEnvironment", "loadedImageNames", YES, @encode(id), 0, {NULL}},
    {"TSEnvironment", "isBeingDebugged", YES, @encode(_Bool), 0, {NULL}},
    {"WCPayTouchIDAuthHelper", "isDeviceJailBreak", YES, @encode(_Bool), 0, {NULL}},
    {"WCPayTouchIDAuthHelper", "isDeviceTouchIDAvailableAndNotJailBreak", YES, @encode(_Bool), 0, {NULL}},
    {"WCPayTouchIDAuthHelper", "isDeviceTouchIDHardwareSupportedAndNotJailBreak", YES, @encode(_Bool), 0, {NULL}},
    {"iAPMgr", "cannotPurchaseDuetoJailbreakPlugin:", NO, @encode(_Bool), 1, {@encode(_Bool)}},
    {"iAPMgr", "RestoreCompletedTransactionsNeedCheckJailBreak:", NO, @encode(long long), 1, {@encode(_Bool)}},
    {"iAPMgr", "Purchase:extInfo:NeedCheckJailBreak:", NO, @encode(long long), 3, {@encode(id), @encode(id), @encode(_Bool)}},
};

#pragma mark - Explicit Logos initialization

%ctor
{
    @autoreleasepool {
        // IPA injectors may ignore the jailbreak loader's filter plist.
        // Permit re-signed bundle identifiers, but never hook app extensions.
        if (![[NSBundle mainBundle].infoDictionary[@"CFBundleExecutable"] isEqualToString:@"WeChat"]) return;
        gLog = os_log_create(WCEB_DOMAIN, "env");
        WCEBLoadConfig();
        if (!gEnabled) return;
        unsigned int installed = 0;
        IMP previous = NULL;
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[0], &previous)) {
            %init(WCEBHook001);
            installed += WCEBRecordInstall(&kHookSpecs[0], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[1], &previous)) {
            %init(WCEBHook002);
            installed += WCEBRecordInstall(&kHookSpecs[1], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[2], &previous)) {
            %init(WCEBHook003);
            installed += WCEBRecordInstall(&kHookSpecs[2], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[3], &previous)) {
            %init(WCEBHook004);
            installed += WCEBRecordInstall(&kHookSpecs[3], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[4], &previous)) {
            %init(WCEBHook005);
            installed += WCEBRecordInstall(&kHookSpecs[4], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[5], &previous)) {
            %init(WCEBHook006);
            installed += WCEBRecordInstall(&kHookSpecs[5], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[6], &previous)) {
            %init(WCEBHook007);
            installed += WCEBRecordInstall(&kHookSpecs[6], previous) ? 1 : 0;
        }
        if (gEnabled && gReceiptView && WCEBPrepare(&kHookSpecs[7], &previous)) {
            %init(WCEBHook008);
            installed += WCEBRecordInstall(&kHookSpecs[7], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[8], &previous)) {
            %init(WCEBHook009);
            installed += WCEBRecordInstall(&kHookSpecs[8], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[9], &previous)) {
            %init(WCEBHook010);
            installed += WCEBRecordInstall(&kHookSpecs[9], previous) ? 1 : 0;
        }
        if (gDeviceIdentity && gEnabled && WCEBPrepare(&kHookSpecs[10], &previous)) {
            %init(WCEBHook011);
            installed += WCEBRecordInstall(&kHookSpecs[10], previous) ? 1 : 0;
        }
        if (gEnabled && gSystemQueries && WCEBPrepare(&kHookSpecs[11], &previous)) {
            %init(WCEBHook012);
            installed += WCEBRecordInstall(&kHookSpecs[11], previous) ? 1 : 0;
        }
        if (gEnabled && gSceneGate && WCEBPrepare(&kHookSpecs[12], &previous)) {
            %init(WCEBHook013);
            installed += WCEBRecordInstall(&kHookSpecs[12], previous) ? 1 : 0;
        }
        if (gEnabled && gSceneGate && WCEBPrepare(&kHookSpecs[13], &previous)) {
            %init(WCEBHook014);
            installed += WCEBRecordInstall(&kHookSpecs[13], previous) ? 1 : 0;
        }
        if (gEnabled && gSceneGate && WCEBPrepare(&kHookSpecs[14], &previous)) {
            %init(WCEBHook015);
            installed += WCEBRecordInstall(&kHookSpecs[14], previous) ? 1 : 0;
        }
        if (gEnabled && gSceneGate && WCEBPrepare(&kHookSpecs[15], &previous)) {
            %init(WCEBHook016);
            installed += WCEBRecordInstall(&kHookSpecs[15], previous) ? 1 : 0;
        }
        if (gEnabled && gSceneGate && WCEBPrepare(&kHookSpecs[16], &previous)) {
            %init(WCEBHook017);
            installed += WCEBRecordInstall(&kHookSpecs[16], previous) ? 1 : 0;
        }
        if (gEnabled && gSceneGate && WCEBPrepare(&kHookSpecs[17], &previous)) {
            %init(WCEBHook018);
            installed += WCEBRecordInstall(&kHookSpecs[17], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[18], &previous)) {
            %init(WCEBHook019);
            installed += WCEBRecordInstall(&kHookSpecs[18], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[19], &previous)) {
            %init(WCEBHook020);
            installed += WCEBRecordInstall(&kHookSpecs[19], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[20], &previous)) {
            %init(WCEBHook021);
            installed += WCEBRecordInstall(&kHookSpecs[20], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[21], &previous)) {
            %init(WCEBHook022);
            installed += WCEBRecordInstall(&kHookSpecs[21], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[22], &previous)) {
            %init(WCEBHook023);
            installed += WCEBRecordInstall(&kHookSpecs[22], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[23], &previous)) {
            %init(WCEBHook024);
            installed += WCEBRecordInstall(&kHookSpecs[23], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[24], &previous)) {
            %init(WCEBHook025);
            installed += WCEBRecordInstall(&kHookSpecs[24], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[25], &previous)) {
            %init(WCEBHook026);
            installed += WCEBRecordInstall(&kHookSpecs[25], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[26], &previous)) {
            %init(WCEBHook027);
            installed += WCEBRecordInstall(&kHookSpecs[26], previous) ? 1 : 0;
        }
        if (gEnabled && gModules && WCEBPrepare(&kHookSpecs[27], &previous)) {
            %init(WCEBHook028);
            installed += WCEBRecordInstall(&kHookSpecs[27], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[28], &previous)) {
            %init(WCEBHook029);
            installed += WCEBRecordInstall(&kHookSpecs[28], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[29], &previous)) {
            %init(WCEBHook030);
            installed += WCEBRecordInstall(&kHookSpecs[29], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[30], &previous)) {
            %init(WCEBHook031);
            installed += WCEBRecordInstall(&kHookSpecs[30], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[31], &previous)) {
            %init(WCEBHook032);
            installed += WCEBRecordInstall(&kHookSpecs[31], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[32], &previous)) {
            %init(WCEBHook033);
            installed += WCEBRecordInstall(&kHookSpecs[32], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[33], &previous)) {
            %init(WCEBHook034);
            installed += WCEBRecordInstall(&kHookSpecs[33], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[34], &previous)) {
            %init(WCEBHook035);
            installed += WCEBRecordInstall(&kHookSpecs[34], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[35], &previous)) {
            %init(WCEBHook036);
            installed += WCEBRecordInstall(&kHookSpecs[35], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[36], &previous)) {
            %init(WCEBHook037);
            installed += WCEBRecordInstall(&kHookSpecs[36], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[37], &previous)) {
            %init(WCEBHook038);
            installed += WCEBRecordInstall(&kHookSpecs[37], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[38], &previous)) {
            %init(WCEBHook039);
            installed += WCEBRecordInstall(&kHookSpecs[38], previous) ? 1 : 0;
        }
        if (gEnabled && gReporting && WCEBPrepare(&kHookSpecs[39], &previous)) {
            %init(WCEBHook040);
            installed += WCEBRecordInstall(&kHookSpecs[39], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[40], &previous)) {
            %init(WCEBHook041);
            installed += WCEBRecordInstall(&kHookSpecs[40], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[41], &previous)) {
            %init(WCEBHook042);
            installed += WCEBRecordInstall(&kHookSpecs[41], previous) ? 1 : 0;
        }
        if (gEnabled && gReporting && WCEBPrepare(&kHookSpecs[42], &previous)) {
            %init(WCEBHook043);
            installed += WCEBRecordInstall(&kHookSpecs[42], previous) ? 1 : 0;
        }
        if (gEnabled && gIntegrity && WCEBPrepare(&kHookSpecs[43], &previous)) {
            %init(WCEBHook044);
            installed += WCEBRecordInstall(&kHookSpecs[43], previous) ? 1 : 0;
        }
        if (gEnabled && gIntegrity && WCEBPrepare(&kHookSpecs[44], &previous)) {
            %init(WCEBHook045);
            installed += WCEBRecordInstall(&kHookSpecs[44], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[45], &previous)) {
            %init(WCEBHook046);
            installed += WCEBRecordInstall(&kHookSpecs[45], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && WCEBPrepare(&kHookSpecs[46], &previous)) {
            %init(WCEBHook047);
            installed += WCEBRecordInstall(&kHookSpecs[46], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[47], &previous)) {
            %init(WCEBHook048);
            installed += WCEBRecordInstall(&kHookSpecs[47], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[48], &previous)) {
            %init(WCEBHook049);
            installed += WCEBRecordInstall(&kHookSpecs[48], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[49], &previous)) {
            %init(WCEBHook050);
            installed += WCEBRecordInstall(&kHookSpecs[49], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[50], &previous)) {
            %init(WCEBHook051);
            installed += WCEBRecordInstall(&kHookSpecs[50], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[51], &previous)) {
            %init(WCEBHook052);
            installed += WCEBRecordInstall(&kHookSpecs[51], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[52], &previous)) {
            %init(WCEBHook053);
            installed += WCEBRecordInstall(&kHookSpecs[52], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[53], &previous)) {
            %init(WCEBHook054);
            installed += WCEBRecordInstall(&kHookSpecs[53], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[54], &previous)) {
            %init(WCEBHook055);
            installed += WCEBRecordInstall(&kHookSpecs[54], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && WCEBPrepare(&kHookSpecs[55], &previous)) {
            %init(WCEBHook056);
            installed += WCEBRecordInstall(&kHookSpecs[55], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[56], &previous)) {
            %init(WCEBHook057);
            installed += WCEBRecordInstall(&kHookSpecs[56], previous) ? 1 : 0;
        }
        if (gClientChecks && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[57], &previous)) {
            %init(WCEBHook058);
            installed += WCEBRecordInstall(&kHookSpecs[57], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[58], &previous)) {
            %init(WCEBHook059);
            installed += WCEBRecordInstall(&kHookSpecs[58], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[59], &previous)) {
            %init(WCEBHook060);
            installed += WCEBRecordInstall(&kHookSpecs[59], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[60], &previous)) {
            %init(WCEBHook061);
            installed += WCEBRecordInstall(&kHookSpecs[60], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[61], &previous)) {
            %init(WCEBHook062);
            installed += WCEBRecordInstall(&kHookSpecs[61], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[62], &previous)) {
            %init(WCEBHook063);
            installed += WCEBRecordInstall(&kHookSpecs[62], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[63], &previous)) {
            %init(WCEBHook064);
            installed += WCEBRecordInstall(&kHookSpecs[63], previous) ? 1 : 0;
        }
        if (gCacheReports && gEnabled && gReporting && WCEBPrepare(&kHookSpecs[64], &previous)) {
            %init(WCEBHook065);
            installed += WCEBRecordInstall(&kHookSpecs[64], previous) ? 1 : 0;
        }
        if (gEnabled && gSignature && WCEBPrepare(&kHookSpecs[65], &previous)) {
            %init(WCEBHook066);
            installed += WCEBRecordInstall(&kHookSpecs[65], previous) ? 1 : 0;
        }
        if (gEnabled && gJailbreak && WCEBPrepare(&kHookSpecs[66], &previous)) {
            %init(WCEBHook067);
            installed += WCEBRecordInstall(&kHookSpecs[66], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[67], &previous)) {
            %init(WCEBHook068);
            installed += WCEBRecordInstall(&kHookSpecs[67], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[68], &previous)) {
            %init(WCEBHook069);
            installed += WCEBRecordInstall(&kHookSpecs[68], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[69], &previous)) {
            %init(WCEBHook070);
            installed += WCEBRecordInstall(&kHookSpecs[69], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[70], &previous)) {
            %init(WCEBHook071);
            installed += WCEBRecordInstall(&kHookSpecs[70], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[71], &previous)) {
            %init(WCEBHook072);
            installed += WCEBRecordInstall(&kHookSpecs[71], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[72], &previous)) {
            %init(WCEBHook073);
            installed += WCEBRecordInstall(&kHookSpecs[72], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[73], &previous)) {
            %init(WCEBHook074);
            installed += WCEBRecordInstall(&kHookSpecs[73], previous) ? 1 : 0;
        }
        if (gEnabled && gReportFields && gReporting && WCEBPrepare(&kHookSpecs[74], &previous)) {
            %init(WCEBHook075);
            installed += WCEBRecordInstall(&kHookSpecs[74], previous) ? 1 : 0;
        }
        if (gDiagnosticsSuppression && gEnabled && WCEBPrepare(&kHookSpecs[75], &previous)) {
            %init(WCEBHook076);
            installed += WCEBRecordInstall(&kHookSpecs[75], previous) ? 1 : 0;
        }
        if (gDiagnosticsSuppression && gEnabled && WCEBPrepare(&kHookSpecs[76], &previous)) {
            %init(WCEBHook077);
            installed += WCEBRecordInstall(&kHookSpecs[76], previous) ? 1 : 0;
        }
        if (gDiagnosticsSuppression && gEnabled && WCEBPrepare(&kHookSpecs[77], &previous)) {
            %init(WCEBHook078);
            installed += WCEBRecordInstall(&kHookSpecs[77], previous) ? 1 : 0;
        }
        if (gDiagnosticsSuppression && gEnabled && WCEBPrepare(&kHookSpecs[78], &previous)) {
            %init(WCEBHook079);
            installed += WCEBRecordInstall(&kHookSpecs[78], previous) ? 1 : 0;
        }
        if (gEnabled && gHeaderEnvironment && gJailbreak && WCEBPrepare(&kHookSpecs[79], &previous)) {
            %init(WCEBHook080);
            installed += WCEBRecordInstall(&kHookSpecs[79], previous) ? 1 : 0;
        }
        if (gEnabled && gHeaderEnvironment && gModules && WCEBPrepare(&kHookSpecs[80], &previous)) {
            %init(WCEBHook081);
            installed += WCEBRecordInstall(&kHookSpecs[80], previous) ? 1 : 0;
        }
        if (gEnabled && gEnvChecks && gHeaderEnvironment && WCEBPrepare(&kHookSpecs[81], &previous)) {
            %init(WCEBHook082);
            installed += WCEBRecordInstall(&kHookSpecs[81], previous) ? 1 : 0;
        }
        if (gEnabled && gPaymentEnvironment && WCEBPrepare(&kHookSpecs[82], &previous)) {
            %init(WCEBHook083);
            installed += WCEBRecordInstall(&kHookSpecs[82], previous) ? 1 : 0;
        }
        if (gEnabled && gPaymentEnvironment && WCEBPrepare(&kHookSpecs[83], &previous)) {
            %init(WCEBHook084);
            installed += WCEBRecordInstall(&kHookSpecs[83], previous) ? 1 : 0;
        }
        if (gEnabled && gPaymentEnvironment && WCEBPrepare(&kHookSpecs[84], &previous)) {
            %init(WCEBHook085);
            installed += WCEBRecordInstall(&kHookSpecs[84], previous) ? 1 : 0;
        }
        if (gEnabled && gPaymentEnvironment && WCEBPrepare(&kHookSpecs[85], &previous)) {
            %init(WCEBHook086);
            installed += WCEBRecordInstall(&kHookSpecs[85], previous) ? 1 : 0;
        }
        if (gEnabled && gPaymentEnvironment && WCEBPrepare(&kHookSpecs[86], &previous)) {
            %init(WCEBHook087);
            installed += WCEBRecordInstall(&kHookSpecs[86], previous) ? 1 : 0;
        }
        if (gEnabled && gPaymentEnvironment && WCEBPrepare(&kHookSpecs[87], &previous)) {
            %init(WCEBHook088);
            installed += WCEBRecordInstall(&kHookSpecs[87], previous) ? 1 : 0;
        }
        os_log_info(gLog, "[WCEB] %s registered=%u maximum=%u (enabled methods: presence/ABI checked)",
                    WCEB_VERSION, installed, (unsigned int)(sizeof(kHookSpecs) / sizeof(kHookSpecs[0])));
    }
}
