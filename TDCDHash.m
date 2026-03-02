#import "TDCDHash.h"
#import "appstoretrollerKiller/TSUtil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <CommonCrypto/CommonDigest.h>

// Code Signing structures (big-endian on disk)
#define CSMAGIC_CODEDIRECTORY        0xfade0c02u
#define CSMAGIC_EMBEDDED_SIGNATURE   0xfade0cc0u

#define CS_HASHTYPE_SHA1             1
#define CS_HASHTYPE_SHA256           2
#define CS_HASHTYPE_SHA256_TRUNCATED 3
#define CS_HASHTYPE_SHA384           4

typedef struct {
    uint32_t type;
    uint32_t offset;
} CS_BlobIndex;

typedef struct {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
    CS_BlobIndex index[];
} CS_SuperBlob;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
    uint32_t hashOffset;
    uint32_t identOffset;
    uint32_t nSpecialSlots;
    uint32_t nCodeSlots;
    uint32_t codeLimit;
    uint8_t  hashSize;
    uint8_t  hashType;
    uint8_t  platform;
    uint8_t  pageSize;
    uint32_t spare2;
} CS_CodeDirectory;

static unsigned hashTypeRank(uint8_t hashType) {
    switch (hashType) {
        case CS_HASHTYPE_SHA1:             return 1;
        case CS_HASHTYPE_SHA256_TRUNCATED: return 2;
        case CS_HASHTYPE_SHA256:           return 3;
        case CS_HASHTYPE_SHA384:           return 4;
        default:                           return 0;
    }
}

static BOOL hashCodeDirectory(const uint8_t *cdBytes, size_t cdLength, uint8_t cdhashOut[TD_CDHASH_LEN]) {
    const CS_CodeDirectory *cd = (const CS_CodeDirectory *)cdBytes;
    switch (cd->hashType) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(cdBytes, (CC_LONG)cdLength, cdhashOut);
            return YES;
        case CS_HASHTYPE_SHA256_TRUNCATED:
        case CS_HASHTYPE_SHA256: {
            uint8_t digest[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(cdBytes, (CC_LONG)cdLength, digest);
            memcpy(cdhashOut, digest, TD_CDHASH_LEN);
            return YES;
        }
        case CS_HASHTYPE_SHA384: {
            uint8_t digest[48];
            CC_SHA384(cdBytes, (CC_LONG)cdLength, digest);
            memcpy(cdhashOut, digest, TD_CDHASH_LEN);
            return YES;
        }
        default:
            return NO;
    }
}

static BOOL processSuperBlob(const uint8_t *sigBlob, size_t sigSize, uint8_t cdhashOut[TD_CDHASH_LEN]) {
    if (sigSize < sizeof(CS_SuperBlob)) return NO;

    const CS_SuperBlob *sb = (const CS_SuperBlob *)sigBlob;
    uint32_t magic = ntohl(sb->magic);

    // Handle raw CodeDirectory (no SuperBlob wrapper)
    if (magic == CSMAGIC_CODEDIRECTORY) {
        uint32_t cdLen = ntohl(((const CS_CodeDirectory *)sigBlob)->length);
        if (cdLen > sigSize) return NO;
        return hashCodeDirectory(sigBlob, cdLen, cdhashOut);
    }

    if (magic != CSMAGIC_EMBEDDED_SIGNATURE) return NO;

    uint32_t count = ntohl(sb->count);
    if (sizeof(CS_SuperBlob) + (size_t)count * sizeof(CS_BlobIndex) > sigSize) return NO;

    unsigned bestRank = 0;
    uint8_t bestHash[TD_CDHASH_LEN] = {0};

    for (uint32_t i = 0; i < count; i++) {
        uint32_t offset = ntohl(sb->index[i].offset);
        if ((size_t)offset + 8 > sigSize) continue;

        const uint8_t *blobPtr = sigBlob + offset;
        uint32_t blobMagic = ntohl(*(const uint32_t *)blobPtr);
        if (blobMagic != CSMAGIC_CODEDIRECTORY) continue;

        uint32_t cdLen = ntohl(*(const uint32_t *)(blobPtr + 4));
        if ((size_t)offset + cdLen > sigSize) continue;
        if (cdLen < sizeof(CS_CodeDirectory)) continue;

        const CS_CodeDirectory *cd = (const CS_CodeDirectory *)blobPtr;
        unsigned rank = hashTypeRank(cd->hashType);
        if (rank > bestRank) {
            uint8_t tmpHash[TD_CDHASH_LEN];
            if (hashCodeDirectory(blobPtr, cdLen, tmpHash)) {
                bestRank = rank;
                memcpy(bestHash, tmpHash, TD_CDHASH_LEN);
            }
        }
    }

    if (bestRank == 0) return NO;
    memcpy(cdhashOut, bestHash, TD_CDHASH_LEN);
    return YES;
}

static BOOL computeCDHashFromMachO(const uint8_t *fileBase, size_t fileSize,
                                    size_t sliceOffset, size_t sliceSize,
                                    uint8_t cdhashOut[TD_CDHASH_LEN]) {
    if (sliceOffset + sliceSize > fileSize || sliceSize < sizeof(struct mach_header))
        return NO;

    const uint8_t *sliceBase = fileBase + sliceOffset;
    const struct mach_header *mh = (const struct mach_header *)sliceBase;

    size_t headerSize;
    if (mh->magic == MH_MAGIC_64) {
        headerSize = sizeof(struct mach_header_64);
    } else if (mh->magic == MH_MAGIC) {
        headerSize = sizeof(struct mach_header);
    } else {
        return NO;
    }

    if (headerSize + mh->sizeofcmds > sliceSize) return NO;

    const uint8_t *lc = sliceBase + headerSize;
    const uint8_t *lcEnd = lc + mh->sizeofcmds;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc + sizeof(struct load_command) > lcEnd) break;
        const struct load_command *cmd = (const struct load_command *)lc;
        if (cmd->cmdsize < sizeof(struct load_command) || lc + cmd->cmdsize > lcEnd) break;

        if (cmd->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command *csCmd = (const struct linkedit_data_command *)lc;
            if ((size_t)csCmd->dataoff + csCmd->datasize > fileSize) return NO;
            return processSuperBlob(fileBase + csCmd->dataoff, csCmd->datasize, cdhashOut);
        }
        lc += cmd->cmdsize;
    }
    return NO;
}

NSString *TDCDHashHexString(NSString *binaryPath) {
    NSData *fileData = [NSData dataWithContentsOfFile:binaryPath
                                              options:NSDataReadingMappedIfSafe
                                                error:nil];
    if (!fileData || fileData.length < 4) return nil;

    const uint8_t *base = (const uint8_t *)fileData.bytes;
    size_t fileSize = fileData.length;
    uint32_t magic = *(const uint32_t *)base;

    uint8_t cdhash[TD_CDHASH_LEN];
    BOOL ok = NO;

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        const struct fat_header *fh = (const struct fat_header *)base;
        uint32_t nfat = (magic == FAT_MAGIC) ? fh->nfat_arch : OSSwapInt32(fh->nfat_arch);
        if (sizeof(struct fat_header) + (size_t)nfat * sizeof(struct fat_arch) > fileSize)
            return nil;

        const struct fat_arch *archs = (const struct fat_arch *)(base + sizeof(struct fat_header));
        for (uint32_t i = 0; i < nfat; i++) {
            cpu_type_t sliceCPU = (magic == FAT_MAGIC) ? archs[i].cputype : (cpu_type_t)OSSwapInt32((uint32_t)archs[i].cputype);
            uint32_t sliceOffset = (magic == FAT_MAGIC) ? archs[i].offset : OSSwapInt32(archs[i].offset);
            uint32_t sliceSize = (magic == FAT_MAGIC) ? archs[i].size : OSSwapInt32(archs[i].size);

            if (sliceCPU == CPU_TYPE_ARM64) {
                ok = computeCDHashFromMachO(base, fileSize, sliceOffset, sliceSize, cdhash);
                break;
            }
        }
        // Fallback: first slice
        if (!ok && nfat > 0) {
            uint32_t off = (magic == FAT_MAGIC) ? archs[0].offset : OSSwapInt32(archs[0].offset);
            uint32_t sz = (magic == FAT_MAGIC) ? archs[0].size : OSSwapInt32(archs[0].size);
            ok = computeCDHashFromMachO(base, fileSize, off, sz, cdhash);
        }
    } else if (magic == MH_MAGIC_64 || magic == MH_MAGIC) {
        ok = computeCDHashFromMachO(base, fileSize, 0, fileSize, cdhash);
    }

    if (!ok) return nil;

    NSMutableString *hex = [NSMutableString stringWithCapacity:TD_CDHASH_LEN * 2];
    for (int i = 0; i < TD_CDHASH_LEN; i++) {
        [hex appendFormat:@"%02x", cdhash[i]];
    }
    return [hex copy];
}

NSUInteger TDInjectTrustcacheForApp(NSString *appPath) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *allFiles = [fm subpathsOfDirectoryAtPath:appPath error:nil];
    NSMutableSet *injectedHashes = [NSMutableSet set];

    for (NSString *relativePath in allFiles) {
        NSString *fullPath = [appPath stringByAppendingPathComponent:relativePath];

        // Quick check: skip non-files and known non-binary extensions
        BOOL isDir = NO;
        [fm fileExistsAtPath:fullPath isDirectory:&isDir];
        if (isDir) continue;

        NSString *ext = [relativePath pathExtension];
        if ([ext isEqualToString:@"plist"] || [ext isEqualToString:@"png"] ||
            [ext isEqualToString:@"jpg"] || [ext isEqualToString:@"car"] ||
            [ext isEqualToString:@"nib"] || [ext isEqualToString:@"storyboardc"] ||
            [ext isEqualToString:@"strings"] || [ext isEqualToString:@"lproj"] ||
            [ext isEqualToString:@"js"] || [ext isEqualToString:@"json"] ||
            [ext isEqualToString:@"xml"] || [ext isEqualToString:@"html"] ||
            [ext isEqualToString:@"css"] || [ext isEqualToString:@"metallib"]) {
            continue;
        }

        // Check Mach-O magic
        FILE *f = fopen([fullPath UTF8String], "rb");
        if (!f) continue;
        uint32_t fileMagic = 0;
        fread(&fileMagic, 4, 1, f);
        fclose(f);

        if (fileMagic != MH_MAGIC_64 && fileMagic != MH_MAGIC &&
            fileMagic != FAT_MAGIC && fileMagic != FAT_CIGAM) {
            continue;
        }

        NSString *cdhash = TDCDHashHexString(fullPath);
        if (!cdhash) {
            NSLog(@"[trolldecrypt] trustcache: failed to compute CDHash for %@", relativePath);
            continue;
        }

        if ([injectedHashes containsObject:cdhash]) continue;
        [injectedHashes addObject:cdhash];

        NSLog(@"[trolldecrypt] trustcache: %@ -> %@", relativePath, cdhash);

        // jbctl trustcache add <cdhash> (needs root)
        int result = spawnRoot(@"/var/jb/basebin/jbctl", @[@"trustcache", @"add", cdhash], nil, nil);
        NSLog(@"[trolldecrypt] trustcache: jbctl add %@ result: %d", cdhash, result);
    }

    NSLog(@"[trolldecrypt] trustcache: injected %lu hashes for %@",
          (unsigned long)injectedHashes.count, [appPath lastPathComponent]);
    return injectedHashes.count;
}
