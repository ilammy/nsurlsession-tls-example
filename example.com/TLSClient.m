#import "TLSClient.h"

@import CommonCrypto;

@interface TLSClientTask ()

@property (weak) TLSClient *client;

@property (strong) NSURLSessionStreamTask *task;
@property (assign) CertificateValidationHandler handler;

@end

@interface TLSClient ()

@property (strong) NSURLSession *session;

@property (strong) NSMutableDictionary<NSNumber *, TLSClientTask *> *activeTasks;

@end

@implementation TLSClient

- (id)init
{
    self = [super init];
    if (self) {
        NSURLSessionConfiguration *configuration =
            NSURLSessionConfiguration.ephemeralSessionConfiguration;

        configuration.TLSMinimumSupportedProtocolVersion = tls_protocol_version_TLSv12;

        self.session = [NSURLSession sessionWithConfiguration:configuration
                                                     delegate:self
                                                delegateQueue:nil];

        self.activeTasks = [NSMutableDictionary new];
    }
    return self;
}

- (void)finish
{
    [self.session finishTasksAndInvalidate];
}

- (TLSClientTask *)connectToHost:(NSString *)host andPort:(NSInteger)port
           withValidationHandler:(CertificateValidationHandler)handler
{
    TLSClientTask *task = [TLSClientTask new];
    task.client = self;
    task.task = [self.session streamTaskWithHostName:host port:port];
    task.handler = handler;
    return task;
}

// MARK: - NSURLSessionDelegate

- (void)    URLSession:(NSURLSession *)session
                  task:(NSURLSessionTask *)task
   didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
     completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                 NSURLCredential *credential))completionHandler
{
    // Check that this request is for something we can handle. If it's not
    // TLS ceritificate verification then do whatever the system wants to.
    if (![challenge.protectionSpace.authenticationMethod
          isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    // Get server trust source and check that it has at least one cert for us.
    // If it's somehow empty then it's the server's fault.
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    CFIndex certificateCount = SecTrustGetCertificateCount(trust);
    if (certificateCount < 1) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }

    // Get the leaf certificate we're verifying.
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, 0);

    // Get DER-encoded X.509 data of the certificate, compute its fingerprint.
    CFDataRef certificateData = SecCertificateCopyData(certificate);
    NSMutableData *fingerprint = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(CFDataGetBytePtr(certificateData),
              (CC_LONG)CFDataGetLength(certificateData),
              fingerprint.mutableBytes);
    CFRelease(certificateData);

    // Other information is harder. Extract a dictionary with the stuff we need.
    NSArray<NSString *> *keys = @[
        (NSString *)kSecOIDCommonName,
        (NSString *)kSecOIDSubjectAltName,
        (NSString *)kSecOIDX509V1ValidityNotAfter,
        (NSString *)kSecOIDX509V1ValidityNotBefore,
    ];
    CFDictionaryRef values = SecCertificateCopyValues(certificate,
                                                      (CFArrayRef)keys,
                                                      nil);
    // If we failed to extract the values we need, this is a failure.
    if (!values) {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
        return;
    }
    BOOL error = NO;
    int64_t validNotAfter =
        extractUnixTime(CFDictionaryGetValue(values, kSecOIDX509V1ValidityNotAfter),
                        &error);
    int64_t validNotBefore =
        extractUnixTime(CFDictionaryGetValue(values, kSecOIDX509V1ValidityNotBefore),
                        &error);
    NSArray<NSString *> *hostnames = extractHostnames(values);
    CFRelease(values);

    // Apple thinks different and uses a different epoch from normal people.
    int64_t verificationUnixTime = (int64_t)SecTrustGetVerifyTime(trust)
                                 + (int64_t)kCFAbsoluteTimeIntervalSince1970;

    BOOL certificateTrusted = NO;

    // Once we've assembled all the prerequisites, look for the task handler,
    // and invoke it.
    NSNumber *taskID = [NSNumber numberWithUnsignedInteger:task.taskIdentifier];
    TLSClientTask *clientTask = [self.activeTasks objectForKey:taskID];
    if (clientTask && clientTask.handler) {
        certificateTrusted = clientTask.handler(fingerprint,
                                                hostnames,
                                                validNotBefore,
                                                validNotAfter,
                                                verificationUnixTime);
    }

    // And finally, call completion handler for verification.
    if (certificateTrusted) {
        // TODO: construct credential?
        completionHandler(NSURLSessionAuthChallengeUseCredential, nil);
    } else {
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

static int64_t extractUnixTime(CFDictionaryRef validity, BOOL *error)
{
    CFStringRef type = CFDictionaryGetValue(validity, kSecPropertyKeyType);
    if (type != kSecPropertyTypeNumber) {
        *error = YES;
        return 0;
    }
    CFNumberRef value = CFDictionaryGetValue(validity, kSecPropertyKeyValue);
    int64_t timestamp = 0;
    CFNumberGetValue(value, kCFNumberSInt64Type, &timestamp);
    return timestamp + (int64_t)kCFAbsoluteTimeIntervalSince1970;
}

static NSArray<NSString *> *extractHostnames(CFDictionaryRef values)
{
    NSMutableSet<NSString *> *hostnames = [NSMutableSet new];
    CFDictionaryRef san = CFDictionaryGetValue(values, kSecOIDSubjectAltName);
    if (san) {
        CFStringRef dnsName = (CFStringRef)@"DNS Name";
        CFArrayRef values = CFDictionaryGetValue(san, kSecPropertyKeyValue);
        CFIndex count = CFArrayGetCount(values);
        for (CFIndex i = 0; i < count; i++) {
            CFDictionaryRef value = CFArrayGetValueAtIndex(values, i);
            CFStringRef label = CFDictionaryGetValue(value, kSecPropertyKeyLabel);
            if (CFStringCompare(label, dnsName, 0) == kCFCompareEqualTo) {
                CFStringRef hostname = CFDictionaryGetValue(value, kSecPropertyKeyValue);
                [hostnames addObject:(__bridge NSString *)hostname];
            }
        }
    }
    CFDictionaryRef commonName = CFDictionaryGetValue(values, kSecOIDCommonName);
    if (commonName) {
        CFStringRef value = CFDictionaryGetValue(commonName, kSecPropertyKeyValue);
        [hostnames addObject:(__bridge NSString *)value];
    }
    NSMutableArray<NSString *> *hostnameList =
        [[NSMutableArray alloc] initWithCapacity:hostnames.count];
    for (NSString *hostname in hostnames) {
        [hostnameList addObject:hostname];
    }
    return hostnameList;
}

// MARK: - NSUrlSessionTaskDelegate

- (void)    URLSession:(NSURLSession *)session
                  task:(NSURLSessionTask *)task
  didCompleteWithError:(NSError *)error
{
    NSNumber *taskID = [NSNumber numberWithUnsignedInteger:task.taskIdentifier];
    [self.activeTasks removeObjectForKey:taskID];
}

@end

// MARK: - TLSClientTask

@implementation TLSClientTask

- (void)establishConnection
{
    NSNumber *taskID = [NSNumber numberWithUnsignedInteger:self.task.taskIdentifier];
    [self.client.activeTasks setObject:self
                                forKey:taskID];

    [self.task startSecureConnection];
    [self.task resume];
}

- (void)writeData:(NSData *)data
completionHandler:(void (^) (NSError * _Nullable error))handler
{
    [self.task writeData:data
                 timeout:0
       completionHandler:handler];
}

- (void)readMaxData:(NSUInteger)maxData
  completionHandler:(void (^) (NSData *data, BOOL atEOF,
                               NSError * _Nullable error))handler
{
    [self.task readDataOfMinLength:0
                         maxLength:maxData
                           timeout:0
                 completionHandler:handler];
}

- (void)closeRead
{
    [self.task closeRead];
}

- (void)closeWrite
{
    [self.task closeWrite];
}

@end
