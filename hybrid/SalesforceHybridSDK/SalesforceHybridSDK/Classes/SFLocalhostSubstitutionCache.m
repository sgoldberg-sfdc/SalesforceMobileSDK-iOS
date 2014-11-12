/*
 Copyright (c) 2014, salesforce.com, inc. All rights reserved.
 
 Redistribution and use of this software in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this list of conditions
 and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of
 conditions and the following disclaimer in the documentation and/or other materials provided
 with the distribution.
 * Neither the name of salesforce.com, inc. nor the names of its contributors may be used to
 endorse or promote products derived from this software without specific prior written
 permission of salesforce.com, inc.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#import <MobileCoreServices/MobileCoreServices.h>
#import "SFLocalhostSubstitutionCache.h"

#define WWW_DIR @"www"
#define LOCALHOST_PATH @"/localhost"

@implementation SFLocalhostSubstitutionCache

- (NSString *)mimeTypeForPath:(NSString *)filePath
{
    CFStringRef fileExtension = (__bridge CFStringRef)[filePath pathExtension];
    CFStringRef UTI = UTTypeCreatePreferredIdentifierForTag(kUTTagClassFilenameExtension, fileExtension, NULL);
    CFStringRef MIMEType = UTTypeCopyPreferredTagWithClass(UTI, kUTTagClassMIMEType);
    CFRelease(UTI);
    return (__bridge_transfer NSString *)MIMEType;
}

- (NSString*)pathForResource:(NSString*)resourcepath
{
    NSBundle* mainBundle = [NSBundle mainBundle];
    
    // When passed @"" returned full path to www directory
    if ([resourcepath length] == 0) {
        return [[[mainBundle bundlePath] stringByAppendingPathComponent:WWW_DIR] stringByStandardizingPath];
    }
    
    // Otherwise
    NSString* filename = [resourcepath lastPathComponent];
    NSString* directory = [WWW_DIR stringByAppendingString:[resourcepath substringToIndex:[resourcepath length] - [filename length]]];
    return [[mainBundle pathForResource:filename ofType:@"" inDirectory:directory] stringByStandardizingPath];
}

- (NSCachedURLResponse *)cachedResponseForRequest:(NSURLRequest *)request
{
    NSURL* url = [request URL];
    
    NSString *path = url.path;
    
    // Not a localhost request
    if (![path hasPrefix:LOCALHOST_PATH]) {
        return [super cachedResponseForRequest:request];
    }
    
    // Localhost request
    NSString* urlPath = [[url path] stringByReplacingOccurrencesOfString:LOCALHOST_PATH withString:@""];
    NSString* filePath = [self pathForResource:urlPath];
    NSString* wwwDirPath = [self pathForResource:@""];
    
    NSData* data = nil;
    NSString* mimeType = @"text/plain";
    if (![filePath hasPrefix:wwwDirPath]) {
        [self log:SFLogLevelError format:@"Trying to access files outside www: %@", url];
    }
    else if (![[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        [self log:SFLogLevelError format:@"Trying to access non-existent file: %@", url];
    }
    else {
        data = [NSData dataWithContentsOfFile:filePath];
        mimeType = [self mimeTypeForPath:filePath];
        [self log:SFLogLevelInfo format:@"Loading local file: %@", urlPath];
    }
    
    NSURLResponse *response = [[NSURLResponse alloc]
                               initWithURL:[request URL]
                               MIMEType:mimeType
                               expectedContentLength:[data length]
                               textEncodingName:@"utf-8"];
    
    return [[NSCachedURLResponse alloc] initWithResponse:response data:data];
}

@end
