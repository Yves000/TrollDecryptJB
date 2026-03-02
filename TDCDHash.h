#pragma once
#import <Foundation/Foundation.h>

#define TD_CDHASH_LEN 20

/**
 * Returns the CDHash as a lowercase hex NSString (40 chars),
 * or nil on failure. Picks the arm64 slice for fat binaries.
 */
NSString * _Nullable TDCDHashHexString(NSString * _Nonnull binaryPath);

/**
 * Injects CDHashes for all Mach-O binaries in an .app bundle into
 * the kernel trustcache via jbctl. Returns the number of hashes injected.
 */
NSUInteger TDInjectTrustcacheForApp(NSString * _Nonnull appPath);
