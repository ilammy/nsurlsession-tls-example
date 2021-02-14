#import "AppDelegate.h"
#import "TLSClient.h"

@import CommonCrypto;

@interface AppDelegate ()

@property (strong) IBOutlet NSWindow *window;
@property (strong) IBOutlet NSTextView *textView;

@property (strong) TLSClient *client;

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    self.client = [TLSClient new];

    TLSClientTask *task =
        [self.client connectToHost:@"example.com"
                           andPort:443
             withValidationHandler:^BOOL(NSData *sha256finterprint,
                                         NSArray<NSString *> *hostnames,
                                         int64_t validNotBefore,
                                         int64_t validNotAfter,
                                         int64_t currentTime)
        {
            NSLog(@"XXX validate: fingerprint: %@", sha256finterprint);
            NSLog(@"XXX validate: hostnames: %@", hostnames);
            NSLog(@"XXX validate: validNotBefore: %lld", validNotBefore);
            NSLog(@"XXX validate: validNotAfter:  %lld", validNotAfter);
            NSLog(@"XXX validate: currentTime:    %lld", currentTime);
            return YES;
        }];

    [task establishConnection];

    NSString *requestString =
        @"GET / HTTP/1.0\r\n"
        @"Host: example.com\r\n"
        @"Connection: close\r\n"
        @"\r\n";
    NSData *requestData = [requestString dataUsingEncoding:NSUTF8StringEncoding];

    [task writeData:requestData completionHandler:^(NSError *error) {
        // ignore
    }];
    [task closeWrite];

    [self readMoreFromTask:task
                withBuffer:[NSMutableData dataWithCapacity:4096]];
}

- (void)readMoreFromTask:(TLSClientTask *)task
              withBuffer:(NSMutableData *)buffer
{
    [task readMaxData:1024
    completionHandler:^(NSData *data, BOOL atEOF, NSError *error) {
        NSLog(@"XXX task: received %u bytes (error=%@)", (unsigned)data.length, error);
        if (error) {
            return;
        }
        [buffer appendData:data];
        if (atEOF) {
            NSLog(@"XXX task: at EOF");
            [self taskComplete:task withBuffer:buffer];
            [task closeRead];
        } else {
            [self readMoreFromTask:task withBuffer:buffer];
        }
    }];
}

- (void)taskComplete:(TLSClientTask *)task withBuffer:(NSData *)data
{
    NSString *text =
        [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"XXX received:\n%@", text);
    dispatch_async(dispatch_get_main_queue(), ^{
        self.textView.string = text;
    });
}

- (void)applicationWillTerminate:(NSNotification *)aNotification
{
    // nothing
}

@end
