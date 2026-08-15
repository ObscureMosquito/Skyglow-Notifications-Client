#import "SNLogParser.h"

BOOL SNLogParseLine(NSString *line, NSString **outTrimmed, unichar *outLevel) {
    NSRange firstSpace = [line rangeOfString:@" "];
    if (firstSpace.location == NSNotFound || line.length <= firstSpace.location + 1) {
        return NO;
    }
    NSString *afterDate = [line substringFromIndex:firstSpace.location + 1];

    NSRange secondSpace = [afterDate rangeOfString:@" "];
    if (secondSpace.location == NSNotFound) return NO;
    NSString *timePart = [afterDate substringToIndex:secondSpace.location];

    NSString *afterTime = [afterDate substringFromIndex:secondSpace.location + 1];
    NSRange thirdSpace = [afterTime rangeOfString:@" "];
    NSString *afterProc = (thirdSpace.location != NSNotFound)
                        ? [afterTime substringFromIndex:thirdSpace.location + 1]
                        : afterTime;

    if (afterProc.length == 0) return NO;
    if (outLevel) *outLevel = [afterProc characterAtIndex:0];
    if (outTrimmed) *outTrimmed = [NSString stringWithFormat:@"%@ %@", timePart, afterProc];
    return YES;
}

NSString *SNLogDiagnosticCodeForLine(NSString *line) {
    NSRange marker = [line rangeOfString:@"code=SGN_"];
    if (marker.location == NSNotFound) return nil;

    NSUInteger start = marker.location + marker.length - 4;
    NSUInteger end = start;
    while (end < line.length) {
        unichar ch = [line characterAtIndex:end];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') break;
        end++;
    }
    if (end <= start) return nil;
    return [line substringWithRange:NSMakeRange(start, end - start)];
}

NSString *SNLogSubsystemForCode(NSString *code) {
    if (!code.length) return @"Unstructured";
    static NSDictionary *prefixToSubsystem = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        prefixToSubsystem = [@{
            @"SGN_DAEMON_": @"Core",       @"SGN_CONFIG_": @"Core",
            @"SGN_AVAILABILITY_": @"Core", @"SGN_FSM_": @"Core",
            @"SGN_BACKOFF_": @"Core",      @"SGN_KEEPALIVE_": @"Core",
            @"SGN_TOKEN_": @"Core",        @"SGN_SCHEDULED_": @"Core",
            @"SGN_WAKE_": @"Core",         @"SGN_CIRCUIT_": @"Core",
            @"SGN_MIGRATION_": @"Core",
            @"SGN_PROTOCOL_": @"Network",  @"SGN_CONTROL_": @"Network",
            @"SGN_DNS_": @"Network",       @"SGN_REGISTRATION_": @"Network",
            @"SGN_DELIVERY_": @"Delivery",
            @"SGN_DATABASE_": @"Storage",  @"SGN_CRYPTO_": @"Storage",
            @"SGN_DURABLE_": @"Storage",   @"SGN_APP_": @"Storage",
        } retain];
    });
    for (NSString *prefix in prefixToSubsystem) {
        if ([code hasPrefix:prefix]) return prefixToSubsystem[prefix];
    }
    return @"Other";
}

static BOOL SNLogLevelPassesFilter(unichar level, SNLogFilterLevel filter) {
    switch (filter) {
        case SNLogFilterError: return (level == 'E');
        case SNLogFilterWarn:  return (level == 'E' || level == 'W');
        case SNLogFilterInfo:  return (level == 'E' || level == 'W' || level == 'I');
        default:               return YES;
    }
}

static BOOL SNLogSubsystemPassesScope(NSString *subsystem, SNLogScopeFilter filter) {
    switch (filter) {
        case SNLogScopeCore:     return [subsystem isEqualToString:@"Core"];
        case SNLogScopeNetwork:  return [subsystem isEqualToString:@"Network"];
        case SNLogScopeDelivery: return [subsystem isEqualToString:@"Delivery"];
        case SNLogScopeStorage:  return [subsystem isEqualToString:@"Storage"];
        default:                 return YES;
    }
}

BOOL SNLogLinePassesFilters(NSString *line, BOOL parsed, unichar level,
                            NSString *code, NSString *subsystem,
                            SNLogFilterLevel levelFilter,
                            SNLogScopeFilter scopeFilter,
                            NSString *searchText,
                            BOOL allowUnstructured) {
    if (parsed && !SNLogLevelPassesFilter(level, levelFilter)) return NO;
    if (!parsed && levelFilter != SNLogFilterAll) return NO;
    if (!code.length && !allowUnstructured) return NO;
    if (!SNLogSubsystemPassesScope(subsystem, scopeFilter)) return NO;

    if (searchText.length > 0) {
        NSRange r1 = [line rangeOfString:searchText options:NSCaseInsensitiveSearch];
        NSRange r2 = [code rangeOfString:searchText options:NSCaseInsensitiveSearch];
        NSRange r3 = [subsystem rangeOfString:searchText options:NSCaseInsensitiveSearch];
        if (r1.location == NSNotFound && r2.location == NSNotFound && r3.location == NSNotFound) {
            return NO;
        }
    }
    return YES;
}

NSString *SNLogRenderTail(NSArray *lines,
                          SNLogFilterLevel levelFilter,
                          SNLogScopeFilter scopeFilter,
                          NSString *searchText,
                          NSUInteger *countOut) {
    NSMutableString *out = [NSMutableString string];
    NSUInteger shown = 0;

    for (NSString *line in lines) {
        if (line.length == 0) continue;

        NSString *trimmed = nil;
        unichar level = 0;
        BOOL parsed = SNLogParseLine(line, &trimmed, &level);
        NSString *display = parsed ? trimmed : line;
        NSString *code = SNLogDiagnosticCodeForLine(display);
        NSString *subsystem = SNLogSubsystemForCode(code);

        if (!SNLogLinePassesFilters(display, parsed, level, code, subsystem,
                                    levelFilter, scopeFilter, searchText, YES)) {
            continue;
        }

        [out appendString:display];
        [out appendString:@"\n"];
        shown++;
    }

    if (out.length == 0) {
        BOOL hasActiveFilter = (levelFilter != SNLogFilterAll ||
                                scopeFilter != SNLogScopeAll ||
                                searchText.length > 0);
        [out appendString:!hasActiveFilter
            ? @"\nLog file is empty or has not been created yet."
            : @"\nNo matching lines in the current tail window."];
    }

    if (countOut) *countOut = shown;
    return out;
}

NSString *SNLogDiagnosticSummary(NSArray *lines,
                                 SNLogFilterLevel levelFilter,
                                 SNLogScopeFilter scopeFilter,
                                 NSString *searchText,
                                 BOOL applyFilters,
                                 NSUInteger *countOut) {
    NSMutableDictionary *codeCounts = [NSMutableDictionary dictionary];
    NSMutableDictionary *codeLevels = [NSMutableDictionary dictionary];
    NSMutableDictionary *codeSubsystems = [NSMutableDictionary dictionary];
    NSMutableDictionary *subsystemCounts = [NSMutableDictionary dictionary];
    NSUInteger shown = 0;
    NSUInteger errors = 0, warnings = 0, infos = 0, debug = 0, trace = 0;

    for (NSString *line in lines) {
        if (line.length == 0) continue;

        NSString *trimmed = nil;
        unichar level = 0;
        BOOL parsed = SNLogParseLine(line, &trimmed, &level);
        NSString *display = parsed ? trimmed : line;
        NSString *code = SNLogDiagnosticCodeForLine(display);
        if (!code.length) continue;

        NSString *subsystem = SNLogSubsystemForCode(code);
        if (applyFilters &&
            !SNLogLinePassesFilters(display, parsed, level, code, subsystem,
                                    levelFilter, scopeFilter, searchText, NO)) {
            continue;
        }

        NSNumber *count = [codeCounts objectForKey:code];
        [codeCounts setObject:[NSNumber numberWithUnsignedInteger:[count unsignedIntegerValue] + 1]
                       forKey:code];
        [codeLevels setObject:[NSString stringWithFormat:@"%C", level] forKey:code];
        [codeSubsystems setObject:subsystem forKey:code];

        NSNumber *subCount = [subsystemCounts objectForKey:subsystem];
        [subsystemCounts setObject:[NSNumber numberWithUnsignedInteger:[subCount unsignedIntegerValue] + 1]
                            forKey:subsystem];

        switch (level) {
            case 'E': errors++; break;
            case 'W': warnings++; break;
            case 'I': infos++; break;
            case 'D': debug++; break;
            case 'T': trace++; break;
            default: break;
        }
        shown++;
    }

    NSMutableString *out = [NSMutableString string];
    if (shown == 0) {
        [out appendString:@"\nNo structured diagnostics match the current filters."];
        if (countOut) *countOut = 0;
        return out;
    }

    [out appendString:@"Diagnostic Summary\n\n"];
    [out appendFormat:@"Total: %lu\n", (unsigned long)shown];
    [out appendFormat:@"Severity: E=%lu W=%lu I=%lu D=%lu T=%lu\n\n",
                      (unsigned long)errors,
                      (unsigned long)warnings,
                      (unsigned long)infos,
                      (unsigned long)debug,
                      (unsigned long)trace];

    [out appendString:@"Subsystems\n"];
    NSArray *subsystems = [[subsystemCounts allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for (NSString *subsystem in subsystems) {
        [out appendFormat:@"%@: %@\n", subsystem, [subsystemCounts objectForKey:subsystem]];
    }

    [out appendString:@"\nCodes\n"];
    NSArray *codes = [[codeCounts allKeys] sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
        NSUInteger ca = [[codeCounts objectForKey:a] unsignedIntegerValue];
        NSUInteger cb = [[codeCounts objectForKey:b] unsignedIntegerValue];
        if (ca > cb) return NSOrderedAscending;
        if (ca < cb) return NSOrderedDescending;
        return [a compare:b];
    }];

    for (NSString *code in codes) {
        [out appendFormat:@"%@ %@ %@ %@\n",
                          [codeCounts objectForKey:code],
                          [codeLevels objectForKey:code],
                          [codeSubsystems objectForKey:code],
                          code];
    }

    if (countOut) *countOut = shown;
    return out;
}
