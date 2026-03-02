#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <rootless.h>

@interface MIBundle : NSObject
- (BOOL)isWatchApp;
@end

static NSString *iosVersion = nil;
static BOOL updatesEnabled = NO;
static BOOL visionOSEnabled = NO;

%group appstoredHooks

%hook NSMutableURLRequest

- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field
{
    if (iosVersion != nil) {
        if (updatesEnabled == YES) {
            if ([field isEqualToString:@"User-Agent"]) {
                // NSLog(@"[TrollDecrypt] Spoofing iOS version: iOS/%@", iosVersion);
                value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? " withString:[NSString stringWithFormat:@"iOS/%@ ", iosVersion] options:NSRegularExpressionSearch range:NSMakeRange(0, [value length])];
            }
        } else {
            if ([[self.URL absoluteString] containsString:@"WebObjects/MZBuy.woa/wa/buyProduct"]) {
                if ([field isEqualToString:@"User-Agent"]) {
                    // NSLog(@"[TrollDecrypt] Spoofing iOS version for buyProduct: iOS/%@", iosVersion);
                    value = [value stringByReplacingOccurrencesOfString:@"iOS/.*? " withString:[NSString stringWithFormat:@"iOS/%@ ", iosVersion] options:NSRegularExpressionSearch range:NSMakeRange(0, [value length])];
                }
            }
        }
    }
    %orig(value, field);
}

%end

%end

%group installdOSHooks

%hook MIBundle

-(BOOL)_isMinimumOSVersion:(id)arg1 applicableToOSVersion:(id)arg2 requiredOS:(unsigned long long)arg3 error:(id*)arg4
{
    NSLog(@"[TrollDecrypt] installd: _isMinimumOSVersion: %@ osVer: %@ requiredOS: %llu", arg1, arg2, arg3);
    if ([self isWatchApp]) {
        return %orig(arg1, arg2, arg3, arg4);
    }
    return YES;
}

-(BOOL)isMinimumOSVersion:(id)arg1 applicableToOSVersion:(id)arg2 error:(id*)arg3
{
    NSLog(@"[TrollDecrypt] installd: isMinimumOSVersion: %@ osVer: %@", arg1, arg2);
    if ([self isWatchApp]) {
        return %orig(arg1, arg2, arg3);
    }
    return YES;
}

-(BOOL)isApplicableToCurrentOSVersionWithError:(id*)error {
    NSLog(@"[TrollDecrypt] installd: bypassing isApplicableToCurrentOSVersionWithError");
    return YES;
}

-(BOOL)isApplicableToOSVersion:(id)arg1 error:(id*)arg2 {
    NSLog(@"[TrollDecrypt] installd: bypassing isApplicableToOSVersion: %@", arg1);
    return YES;
}

%end

%end

%group installdVisionOSHooks

%hook MIBundle

// Bypass device family check (allows visionOS UIDeviceFamily=7 on iPhone)
-(BOOL)isApplicableToCurrentDeviceFamilyWithError:(id*)error {
    NSLog(@"[TrollDecrypt] installd: bypassing device family check (visionOS)");
    return YES;
}

-(BOOL)isCompatibleWithDeviceFamily:(int)family {
    NSLog(@"[TrollDecrypt] installd: bypassing device family=%d check (visionOS)", family);
    return YES;
}

// Bypass device capabilities check (visionOS apps may require unavailable capabilities)
-(BOOL)isApplicableToCurrentDeviceCapabilitiesWithError:(id*)error {
    NSLog(@"[TrollDecrypt] installd: bypassing device capabilities check (visionOS)");
    return YES;
}

%end

%end

%ctor {

    // Use our preference file path
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @(0644)} ofItemAtPath:ROOT_PATH_NS(@"/var/mobile/Library/Preferences/com.trolldecrypt.hook.plist") error:nil];
    NSDictionary *prefs = [NSDictionary dictionaryWithContentsOfFile:ROOT_PATH_NS(@"/var/mobile/Library/Preferences/com.trolldecrypt.hook.plist")];
    
    NSLog(@"[TrollDecrypt] ctor loading, prefs: %@", prefs);

    // Check if hook is enabled (default: disabled)
    if (![prefs objectForKey:@"hookEnabled"] || ![[prefs objectForKey:@"hookEnabled"] boolValue]) {
        NSLog(@"[TrollDecrypt] Hook not enabled, returning");
        return;
    }
    
    // Get custom iOS version (default: 99.0.0 if not set)
    iosVersion = [prefs objectForKey:@"iOSVersion"];
    if (iosVersion == nil || [iosVersion length] == 0) {
        iosVersion = @"99.0.0";
    }
    
    // Get updates enabled flag (default: NO)
    updatesEnabled = [[prefs objectForKey:@"updatesEnabled"] boolValue];

    // Get visionOS enabled flag (default: NO)
    visionOSEnabled = [[prefs objectForKey:@"visionOSEnabled"] boolValue];

    NSLog(@"[TrollDecrypt] Hook enabled - iOS version: %@, updatesEnabled: %d, visionOSEnabled: %d", iosVersion, updatesEnabled, visionOSEnabled);


    %init(appstoredHooks);
    %init(installdOSHooks);
    if (visionOSEnabled) {
        %init(installdVisionOSHooks);
    }
}

