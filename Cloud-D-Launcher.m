#import <Cocoa/Cocoa.h>
#import <unistd.h>

@interface LauncherDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) NSTimer *healthTimer;
@property(nonatomic, strong) NSDate *healthDeadline;
@property(nonatomic, copy) NSString *generatedStaffRegistrationCode;
@property(nonatomic, assign) BOOL checkingHealth;
@end

@implementation LauncherDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [self showStartingWindow];
    [self installAndStartBackgroundService];
}

- (void)showStartingWindow {
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 430, 142)
                                              styleMask:NSWindowStyleMaskTitled
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    self.window.title = @"Cloud-D";
    self.window.releasedWhenClosed = NO;

    NSProgressIndicator *spinner = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(28, 60, 20, 20)];
    spinner.style = NSProgressIndicatorStyleSpinning;
    spinner.controlSize = NSControlSizeRegular;
    [spinner startAnimation:nil];
    [self.window.contentView addSubview:spinner];

    NSTextField *message = [NSTextField labelWithString:@"Starting Cloud-D…\nFirst launch may take a minute while setup completes."];
    message.frame = NSMakeRect(62, 43, 340, 58);
    message.maximumNumberOfLines = 2;
    message.lineBreakMode = NSLineBreakByWordWrapping;
    [self.window.contentView addSubview:message];

    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)installAndStartBackgroundService {
    NSURL *bundledProject = [[[NSBundle mainBundle] resourceURL] URLByAppendingPathComponent:@"CloudDProject"];
    NSString *runtimePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/Cloud-D"];
    if (![self copyBundledProject:bundledProject toRuntimePath:runtimePath]) {
        [self showFailure];
        return;
    }

    NSString *home = NSHomeDirectory();
    NSString *dataPath = [home stringByAppendingPathComponent:@".cloud-d"];
    NSString *agentsPath = [home stringByAppendingPathComponent:@"Library/LaunchAgents"];
    NSString *plistPath = [agentsPath stringByAppendingPathComponent:@"edu.psgtech.cloudd.plist"];
    NSString *scriptPath = [runtimePath stringByAppendingPathComponent:@"Run-Cloud-D-Background-macOS.sh"];
    NSError *error = nil;
    NSFileManager *files = [NSFileManager defaultManager];
    if (![files createDirectoryAtPath:dataPath withIntermediateDirectories:YES attributes:nil error:&error] ||
        ![files createDirectoryAtPath:agentsPath withIntermediateDirectories:YES attributes:nil error:&error]) {
        [self showFailure];
        return;
    }
    NSString *codePath = [dataPath stringByAppendingPathComponent:@"staff-registration-code"];
    if (![files fileExistsAtPath:codePath]) {
        NSString *alphabet = @"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        NSMutableString *randomPart = [NSMutableString stringWithCapacity:32];
        for (NSUInteger index = 0; index < 32; index++) {
            [randomPart appendFormat:@"%C", [alphabet characterAtIndex:arc4random_uniform((uint32_t)alphabet.length)]];
        }
        self.generatedStaffRegistrationCode = [NSString stringWithFormat:@"CLOUD-D-%@", randomPart];
        if (![self.generatedStaffRegistrationCode writeToFile:codePath atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
            [self showFailure];
            return;
        }
        [files setAttributes:@{NSFilePosixPermissions: @0600} ofItemAtPath:codePath error:nil];
    }

    NSDictionary *agent = @{
        @"Label": @"edu.psgtech.cloudd",
        @"ProgramArguments": @[@"/bin/zsh", @"-l", scriptPath],
        @"WorkingDirectory": runtimePath,
        @"RunAtLoad": @YES,
        @"KeepAlive": @{@"SuccessfulExit": @NO},
        @"ThrottleInterval": @30,
        @"StandardOutPath": [dataPath stringByAppendingPathComponent:@"server.log"],
        @"StandardErrorPath": [dataPath stringByAppendingPathComponent:@"server.log"],
        @"ProcessType": @"Background"
    };
    NSData *plist = [NSPropertyListSerialization dataWithPropertyList:agent
                                                                format:NSPropertyListXMLFormat_v1_0
                                                               options:0
                                                                 error:&error];
    if (!plist || ![plist writeToFile:plistPath options:NSDataWritingAtomic error:&error]) {
        [self showFailure];
        return;
    }

    NSString *domain = [NSString stringWithFormat:@"gui/%d", getuid()];
    [self runLaunchctl:@[@"bootout", domain, plistPath]];
    if (![self runLaunchctl:@[@"bootstrap", domain, plistPath]]) {
        [self showFailure];
        return;
    }

    self.healthDeadline = [NSDate dateWithTimeIntervalSinceNow:600];
    self.healthTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                                       target:self
                                                     selector:@selector(checkServiceHealth)
                                                     userInfo:nil
                                                      repeats:YES];
    [self checkServiceHealth];
}

- (BOOL)copyBundledProject:(NSURL *)sourceRoot toRuntimePath:(NSString *)runtimePath {
    NSFileManager *files = [NSFileManager defaultManager];
    NSError *error = nil;
    if (![files createDirectoryAtPath:runtimePath withIntermediateDirectories:YES attributes:nil error:&error]) return NO;

    NSArray<NSString *> *rootFiles = @[@"index.html", @"cloud-d.js", @"requirements.txt", @"Run-Cloud-D-Background-macOS.sh"];
    for (NSString *name in rootFiles) {
        NSString *source = [[sourceRoot URLByAppendingPathComponent:name] path];
        NSString *destination = [runtimePath stringByAppendingPathComponent:name];
        if (![files fileExistsAtPath:source]) return NO;
        if ([files fileExistsAtPath:destination] && ![files removeItemAtPath:destination error:&error]) return NO;
        if (![files copyItemAtPath:source toPath:destination error:&error]) return NO;
    }

    NSString *sourcePackage = [[sourceRoot URLByAppendingPathComponent:@"cloud_d"] path];
    NSString *destinationPackage = [runtimePath stringByAppendingPathComponent:@"cloud_d"];
    if (![files createDirectoryAtPath:destinationPackage withIntermediateDirectories:YES attributes:nil error:&error]) return NO;
    NSDirectoryEnumerator<NSURL *> *items = [files enumeratorAtURL:[NSURL fileURLWithPath:sourcePackage]
                                        includingPropertiesForKeys:@[NSURLIsDirectoryKey]
                                                           options:NSDirectoryEnumerationSkipsHiddenFiles
                                                      errorHandler:^BOOL(NSURL *url, NSError *enumerationError) { return NO; }];
    for (NSURL *item in items) {
        NSString *relativePath = [[item path] substringFromIndex:sourcePackage.length + 1];
        NSString *name = item.lastPathComponent;
        if ([name isEqualToString:@"results"] || [name isEqualToString:@"__pycache__"]) {
            [items skipDescendants];
            continue;
        }
        NSNumber *isDirectory = nil;
        if (![item getResourceValue:&isDirectory forKey:NSURLIsDirectoryKey error:&error]) return NO;
        NSString *destination = [destinationPackage stringByAppendingPathComponent:relativePath];
        if (isDirectory.boolValue) {
            if (![files createDirectoryAtPath:destination withIntermediateDirectories:YES attributes:nil error:&error]) return NO;
        } else if ([item.pathExtension isEqualToString:@"py"]) {
            NSString *parent = [destination stringByDeletingLastPathComponent];
            if (![files createDirectoryAtPath:parent withIntermediateDirectories:YES attributes:nil error:&error]) return NO;
            if ([files fileExistsAtPath:destination] && ![files removeItemAtPath:destination error:&error]) return NO;
            if (![files copyItemAtPath:item.path toPath:destination error:&error]) return NO;
        }
    }
    return YES;
}

- (BOOL)runLaunchctl:(NSArray<NSString *> *)arguments {
    NSTask *task = [[NSTask alloc] init];
    task.executableURL = [NSURL fileURLWithPath:@"/bin/launchctl"];
    task.arguments = arguments;
    NSError *error = nil;
    if (![task launchAndReturnError:&error]) return NO;
    [task waitUntilExit];
    return task.terminationStatus == 0;
}

- (void)checkServiceHealth {
    if (self.checkingHealth) return;
    if ([[NSDate date] compare:self.healthDeadline] != NSOrderedAscending) {
        [self.healthTimer invalidate];
        [self showFailure];
        return;
    }

    self.checkingHealth = YES;
    NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:8765/api/health"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:1.0];
    [[[NSURLSession sharedSession] dataTaskWithRequest:request
                                     completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            self.checkingHealth = NO;
            if ([response isKindOfClass:[NSHTTPURLResponse class]] && ((NSHTTPURLResponse *)response).statusCode == 200) {
                [self.healthTimer invalidate];
                [self showGeneratedRegistrationCodeIfNeeded];
                [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"http://127.0.0.1:8765/"]];
                [NSApp terminate:nil];
            }
        });
    }] resume];
}

- (void)showGeneratedRegistrationCodeIfNeeded {
    if (self.generatedStaffRegistrationCode.length == 0) return;
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"Staff Registration Code created";
    alert.informativeText = [NSString stringWithFormat:@"Save this code for staff signup:\n\n%@\n\nIt is also stored in ~/.cloud-d/staff-registration-code.", self.generatedStaffRegistrationCode];
    [alert addButtonWithTitle:@"Continue"];
    [alert runModal];
}

- (void)showFailure {
    [self.healthTimer invalidate];
    [self.window close];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleWarning;
    alert.messageText = @"Cloud-D couldn't start";
    alert.informativeText = @"Check ~/.cloud-d/server.log for details. Python 3.10 or newer and internet access are needed for first-time setup.";
    [alert addButtonWithTitle:@"Show Logs"];
    [alert addButtonWithTitle:@"Close"];
    if ([alert runModal] == NSAlertFirstButtonReturn) {
        NSString *logsPath = [NSHomeDirectory() stringByAppendingPathComponent:@".cloud-d"];
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:logsPath]];
    }
    [NSApp terminate:nil];
}

@end

int main(void) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        LauncherDelegate *delegate = [[LauncherDelegate alloc] init];
        [NSApp setDelegate:delegate];
        [NSApp run];
    }
    return 0;
}
