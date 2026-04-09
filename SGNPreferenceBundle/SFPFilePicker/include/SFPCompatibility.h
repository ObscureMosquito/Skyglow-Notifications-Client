#import <Availability.h>

#ifndef SFP_COMPATIBILITY_H
#define SFP_COMPATIBILITY_H

#if __IPHONE_OS_VERSION_MAX_ALLOWED < 69999
    #define NSTextAlignmentRight UITextAlignmentRight
    #define NSTextAlignmentCenter UITextAlignmentCenter
    #define NSLineBreakByCharWrapping UILineBreakModeCharacterWrap
    #define NSLineBreakByTruncatingTail UILineBreakModeTailTruncation
    
    typedef UITextAlignment NSTextAlignment;
    typedef UILineBreakMode NSLineBreakMode;
#endif

#endif