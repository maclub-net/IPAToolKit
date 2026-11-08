#import "anisette.h"

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <objc/message.h>
#import <stdlib.h>
#import <string.h>

static NSString *const CSAPAnisetteFramework =
    @"/System/Library/PrivateFrameworks/AppleMediaServices.framework/AppleMediaServices";
static NSString *const CSAPAnisetteClass = @"AMSAnisette";
static NSString *const CSAPAnisetteSelector = @"_headersForRequest:account:type:";
static NSString *const CSAPAMDField = @"X-Apple-AMD";
static NSString *const CSAPAMDProofField = @"X-Apple-AMD-M";

static BOOL CSAPValidHeaderValue(id value) {
    if (![value isKindOfClass:[NSString class]]) {
        return NO;
    }

    NSString *text = (NSString *)value;
    if (text.length == 0 || text.length > 8192) {
        return NO;
    }

    NSCharacterSet *invalid = [NSCharacterSet controlCharacterSet];
    return [text rangeOfCharacterFromSet:invalid].location == NSNotFound;
}

int csap_store_amd_headers(const char *endpoint, char **amd, char **amd_m) {
    if (endpoint == NULL || amd == NULL || amd_m == NULL) {
        return 1;
    }

    *amd = NULL;
    *amd_m = NULL;

    // 框架与类会活到进程结束，句柄有意不关闭。
    static void *framework = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        framework = dlopen(CSAPAnisetteFramework.UTF8String, RTLD_NOW | RTLD_LOCAL);
    });
    if (framework == NULL) {
        return 2;
    }

    Class anisette = NSClassFromString(CSAPAnisetteClass);
    SEL selector = NSSelectorFromString(CSAPAnisetteSelector);
    if (anisette == Nil || ![anisette respondsToSelector:selector]) {
        return 3;
    }

    NSString *endpointString = [NSString stringWithUTF8String:endpoint];
    NSURL *url = endpointString.length > 0 ? [NSURL URLWithString:endpointString] : nil;
    if (url == nil) {
        return 4;
    }

    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    // type 2 请求的是 Store 设备证明，而不是 AuthKit 的 X-Apple-I-MD 证明。
    NSDictionary *headers =
        ((id (*)(id, SEL, id, id, NSInteger))objc_msgSend)((id)anisette, selector, request, nil, 2);
    if (![headers isKindOfClass:[NSDictionary class]]) {
        return 5;
    }

    id values[] = {headers[CSAPAMDField], headers[CSAPAMDProofField]};
    for (NSUInteger index = 0; index < 2; index++) {
        if (!CSAPValidHeaderValue(values[index])) {
            return 6;
        }
    }

    char *copiedAMD = strdup([values[0] UTF8String]);
    char *copiedProof = strdup([values[1] UTF8String]);
    if (copiedAMD == NULL || copiedProof == NULL) {
        free(copiedAMD);
        free(copiedProof);
        return 7;
    }

    *amd = copiedAMD;
    *amd_m = copiedProof;

    return 0;
}

void csap_store_amd_headers_free(char *value) {
    free(value);
}
