#import <Foundation/Foundation.h>
#import "TDUtils.h"
#import "LSApplicationProxy+AltList.h"
#import "TDDumpDecrypted.h"

// Helper function to find tool in common locations
NSString *findTool(NSString *toolName) {
    NSFileManager *fm = [NSFileManager defaultManager];
    
    // Check common locations
    NSArray *searchPaths = @[
        @"/usr/local/bin",
        @"/usr/bin",
        [[NSBundle mainBundle] resourcePath] ?: @"",
        [[NSFileManager defaultManager] currentDirectoryPath],
        @"/var/jb/usr/local/bin",  // For rootless jailbreaks
        @"/usr/bin"
    ];
    
    for (NSString *path in searchPaths) {
        if ([path length] == 0) continue;
        NSString *fullPath = [path stringByAppendingPathComponent:toolName];
        if ([fm fileExistsAtPath:fullPath]) {
            return fullPath;
        }
    }
    
    // Check if tool is in PATH
    NSString *whichPath = [NSString stringWithFormat:@"/usr/bin/which %@", toolName];
    FILE *pipe = popen([whichPath UTF8String], "r");
    if (pipe) {
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            NSString *result = [[NSString stringWithUTF8String:buffer] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            pclose(pipe);
            if ([result length] > 0 && [fm fileExistsAtPath:result]) {
                return result;
            }
        }
        pclose(pipe);
    }
    
    return nil;
}

void printUsage(const char *programName) {
    printf("Usage: %s <bundle_id> <output_folder>\n", programName);
    printf("\n");
    printf("Decrypts an iOS app and creates a decrypted IPA file.\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  bundle_id     - Bundle identifier of the app to decrypt (e.g., com.apple.calculator)\n");
    printf("  output_folder - Path to output folder where the decrypted IPA will be saved\n");
    printf("\n");
    printf("Example:\n");
    printf("  %s com.apple.calculator /var/mobile/Documents/decrypted\n", programName);
}

NSDictionary *getAppInfoFromBundleID(NSString *bundleID) {
    LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
    
    if (!appProxy) {
        fprintf(stderr, "Error: App with bundle ID '%s' not found\n", [bundleID UTF8String]);
        return nil;
    }
    
    NSString *name = [appProxy atl_nameToDisplay];
    NSString *version = [appProxy atl_shortVersionString];
    NSString *executable = appProxy.canonicalExecutablePath;
    
    if (!name || !version || !executable) {
        fprintf(stderr, "Error: Failed to get app information for bundle ID '%s'\n", [bundleID UTF8String]);
        return nil;
    }
    
    NSDictionary *appInfo = @{
        @"bundleID": bundleID,
        @"name": name,
        @"version": version,
        @"executable": executable
    };
    
    return appInfo;
}

void decryptAppCLI(NSDictionary *app, NSString *outputFolder) {
    NSString *bundleID = app[@"bundleID"];
    NSString *name = app[@"name"];
    NSString *version = app[@"version"];
    
    printf("[trolldecrypt] Starting decryption for: %s (%s)\n", [name UTF8String], [bundleID UTF8String]);
    printf("[trolldecrypt] Version: %s\n", [version UTF8String]);
    
    // Get the app bundle path
    LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
    if (!appProxy) {
        fprintf(stderr, "[trolldecrypt] Error: Failed to get app proxy for %s\n", [bundleID UTF8String]);
        exit(1);
    }
    
    NSString *appPath = [appProxy bundleURL].path;
    if (!appPath) {
        fprintf(stderr, "[trolldecrypt] Error: Failed to get app path for %s\n", [bundleID UTF8String]);
        exit(1);
    }
    
    printf("[trolldecrypt] App path: %s\n", [appPath UTF8String]);
    
    // Find all mach-o files in the app
    NSArray *machOFiles = findAllMachOFiles(appPath);
    printf("[trolldecrypt] Found %lu mach-o files\n", (unsigned long)machOFiles.count);
    
    if (machOFiles.count == 0) {
        fprintf(stderr, "[trolldecrypt] Error: No mach-o files found in %s\n", [appPath UTF8String]);
        exit(1);
    }
    
    // Create temporary working directory
    NSString *tempDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_decrypt_work", name]];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:tempDir error:nil]; // Clean up any existing temp dir
    NSError *error;
    if (![fm createDirectoryAtPath:tempDir withIntermediateDirectories:YES attributes:nil error:&error]) {
        fprintf(stderr, "[trolldecrypt] Error: Failed to create temp directory: %s\n", [error.localizedDescription UTF8String]);
        exit(1);
    }
    
    // Copy the entire app bundle to temp directory
    NSString *tempAppPath = [tempDir stringByAppendingPathComponent:[appPath lastPathComponent]];
    NSError *copyError;
    if (![fm copyItemAtPath:appPath toPath:tempAppPath error:&copyError]) {
        fprintf(stderr, "[trolldecrypt] Error: Failed to copy app bundle: %s\n", [copyError.localizedDescription UTF8String]);
        exit(1);
    }
    
    printf("[trolldecrypt] Copied app bundle to: %s\n", [tempAppPath UTF8String]);
    
    // Decrypt each mach-o file and replace it in the temp app bundle
    NSUInteger totalFiles = machOFiles.count;
    for (NSUInteger i = 0; i < machOFiles.count; i++) {
        NSString *machOFile = machOFiles[i];
        NSString *relativePath = [machOFile substringFromIndex:appPath.length + 1];
        NSString *tempMachOPath = [tempAppPath stringByAppendingPathComponent:relativePath];
        
        printf("[trolldecrypt] Decrypting [%lu/%lu]: %s\n", (unsigned long)(i + 1), (unsigned long)totalFiles, [relativePath UTF8String]);
        
        // Decrypt the file directly to the temp location (replacing original)
        decryptMachOFile(machOFile, tempMachOPath);
    }
    
    // Create output directory if it doesn't exist
    if (![fm fileExistsAtPath:outputFolder isDirectory:NULL]) {
        if (![fm createDirectoryAtPath:outputFolder withIntermediateDirectories:YES attributes:nil error:&error]) {
            fprintf(stderr, "[trolldecrypt] Error: Failed to create output directory: %s\n", [error.localizedDescription UTF8String]);
            exit(1);
        }
    }
    
    // Create IPA from the modified app bundle
    NSString *ipaFileName = [NSString stringWithFormat:@"%@_%@_decrypted.ipa", name, version];
    NSString *ipaPath = [outputFolder stringByAppendingPathComponent:ipaFileName];
    
    printf("[trolldecrypt] Creating IPA file: %s\n", [ipaPath UTF8String]);
    createIPAFromAppBundle(tempAppPath, ipaPath);
    
    // Clean up temp directory
    [fm removeItemAtPath:tempDir error:nil];
    
    printf("[trolldecrypt] ========================================\n");
    printf("[trolldecrypt] Decryption completed successfully!\n");
    printf("[trolldecrypt] IPA saved to: %s\n", [ipaPath UTF8String]);
    printf("[trolldecrypt] ========================================\n");
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc != 3) {
            printUsage(argv[0]);
            exit(1);
        }
        
        NSString *bundleID = [NSString stringWithUTF8String:argv[1]];
        NSString *outputFolder = [NSString stringWithUTF8String:argv[2]];
        
        // Validate output folder path
        if (![outputFolder hasPrefix:@"/"]) {
            fprintf(stderr, "Error: Output folder must be an absolute path\n");
            exit(1);
        }
        
        // Get app information from bundle ID
        NSDictionary *appInfo = getAppInfoFromBundleID(bundleID);
        if (!appInfo) {
            exit(1);
        }
        
        // Decrypt the app
        decryptAppCLI(appInfo, outputFolder);
        
        return 0;
    }
}
