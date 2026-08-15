#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SNLogFilterLevel) {
    SNLogFilterAll   = 0,
    SNLogFilterInfo  = 1,   /* I, W, E (drops D, T) */
    SNLogFilterWarn  = 2,   /*    W, E */
    SNLogFilterError = 3,   /*       E */
};

typedef NS_ENUM(NSInteger, SNLogScopeFilter) {
    SNLogScopeAll      = 0,
    SNLogScopeCore     = 1,
    SNLogScopeNetwork  = 2,
    SNLogScopeDelivery = 3,
    SNLogScopeStorage  = 4,
};

/** Splits "date time proc L [tag] msg" into "time L [tag] msg" plus severity. */
BOOL SNLogParseLine(NSString *line, NSString **outTrimmed, unichar *outLevel);

NSString *SNLogDiagnosticCodeForLine(NSString *line);
NSString *SNLogSubsystemForCode(NSString *code);

BOOL SNLogLinePassesFilters(NSString *line, BOOL parsed, unichar level,
                            NSString *code, NSString *subsystem,
                            SNLogFilterLevel levelFilter,
                            SNLogScopeFilter scopeFilter,
                            NSString *searchText,
                            BOOL allowUnstructured);

/** Filtered tail text, with an explanatory placeholder when nothing matches. */
NSString *SNLogRenderTail(NSArray *lines,
                          SNLogFilterLevel levelFilter,
                          SNLogScopeFilter scopeFilter,
                          NSString *searchText,
                          NSUInteger *countOut);

NSString *SNLogDiagnosticSummary(NSArray *lines,
                                 SNLogFilterLevel levelFilter,
                                 SNLogScopeFilter scopeFilter,
                                 NSString *searchText,
                                 BOOL applyFilters,
                                 NSUInteger *countOut);
