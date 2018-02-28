/*
 Copyright (c) 2014-present, salesforce.com, inc. All rights reserved.
 
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

#import <Foundation/Foundation.h>
#import "SFEncryptionKey.h"
#import "SFEncryptionKeyPair.h"
#import "SFKeyStoreKey.h"

NS_ASSUME_NONNULL_BEGIN

/**
 Singleton class to manage operations on the key store.
 */
@interface SFKeyStoreManager : NSObject

/**
 @return The singleton instance of the key store manager.
 */
+ (instancetype)sharedInstance;

/**
 Retrieves a key with the given label from the key store, or `nil` depending on the autoCreate value.
 Key will be stored with the default encryption type of 'passcode', and will fall back to a 'generated'
 store encryption if a passcode is not configured.
 @param keyLabel The label associated with the stored key.
 @param create Indicates whether a new key should be created if one does not exist.
 @return The encryption key, or `nil` depending on the autoCreate value.
 */
- (SFEncryptionKey *)retrieveKeyWithLabel:(NSString *)keyLabel autoCreate:(BOOL)create;

/**
 Stores a key with the given label in the key store, with a default encryption type of 'passcode'.  If
 a passcode is not configured, the key will be encrypted with a generated key.
 @param key The encryption key to store.
 @param keyLabel The label associated with the key.
 */
- (void)storeKey:(SFEncryptionKey *)key withLabel:(NSString *)keyLabel;

/**
 Removes the key with the given label from the key store holding passcode-based encrypted keys.
 @param keyLabel The label associated with the key to remove.
 */
- (void)removeKeyWithLabel:(NSString *)keyLabel;

/**
 Determines whether a key with the given label, and encrypted with passcode-based encryption, exists.
 @param keyLabel The label associated with the key to query.
 @return YES if the key exists in the key store, NO otherwise.
 */
- (BOOL)keyWithLabelExists:(NSString *)keyLabel;

/**
 Returns a key with a random value for the key and initialization vector.  The key size
 will be the size for the AES-256 algorithm (kCCKeySizeAES256), and the initialization
 vector will be the block size associated with AES encryption (kCCBlockSizeAES128).
 @return An instance of SFEncryptionKey with the described values.
 */
- (SFEncryptionKey *)keyWithRandomValue;

/**
 Retrieves a key pair with the given label and key length from the key store. If the key
 is not found, this will create it.
 @param keyPairLabel The label associated with the stored key pair.
 @param keyLength The key length associated with the stored key pair.
 @return The encryption key pair
 */
- (SFEncryptionKeyPair *)keyPairWithLabel:(NSString *)keyPairLabel andKeyLength:(NSUInteger)keyLength;

/**
 Retrieves a key pair with the given label, key length, and accessibleAttribute from the key store. If the key
 is not found, this will create it.
 @param keyPairLabel The label associated with the stored key pair.
 @param keyLength The key length associated with the stored key pair.
 @param accessibleAttribute The key accessibility attribute (See kSecAttrAccessible)
 @return The encryption key pair
 */
- (SFEncryptionKeyPair *)keyPairWithLabel:(NSString *)keyPairLabel keyLength:(NSUInteger)keyLength andAccessibleAttribute:(nullable CFTypeRef)accessibleAttribute;

@end

NS_ASSUME_NONNULL_END
