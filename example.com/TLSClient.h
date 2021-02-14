#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TLSClientTask : NSObject

- (void)establishConnection;

- (void)readMaxData:(NSUInteger)maxData
  completionHandler:(void (^) (NSData *data, BOOL atEOF,
                               NSError * _Nullable error))handler;

- (void)writeData:(NSData *)data
completionHandler:(void (^) (NSError * _Nullable error))handler;

- (void)closeRead;
- (void)closeWrite;

@end

typedef BOOL (^CertificateValidationHandler)
    (NSData *sha256finterprint,
     NSArray<NSString *> *hostnames,
     int64_t validNotBefore,
     int64_t validNotAfter,
     int64_t currentTime);

@interface TLSClient : NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate>

- (void)finish;

- (TLSClientTask *)connectToHost:(NSString *)host
                         andPort:(NSInteger)port
           withValidationHandler:(CertificateValidationHandler)handler;

@end

NS_ASSUME_NONNULL_END
