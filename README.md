<div align="center">
<img src="https://github.com/ObscureMosquito/Skyglow-Notifications-Client/blob/main/SGNPreferenceBundle/Resources/icon-settings.png" width=20% height=20%>
<h1>Skyglow Notifications Daemon</h1>
</div>

Simple Cydia Tweak that will open a low power TCP socket and constantly listen for push notifications when deemed appropriate (when network is available as an example), this is made as an alternative to Apple Push Notification Service, adding just a tiny bit of unnoticeable battery overhead, allowing you to host your own free notification server.

## Usage

#### Setting up Skyglow Notifications:

1. Download Skyglow Notifications from Cydia, on thru repo https://cydia.skyglow.es or https://cydia.preloading.dev
2. Enter its preference panel
3. Navigate to "profiles", then add a new profile, and aquire the server certificate in your preferred manner

> [!TIP]
> If you see a "Port" field, you are using an outdated version of Skyglow Notifications. Please update your version of skyglow notifications from Cydia

4. Hit the register button, after the process, you can see registration details under each profile
5. Toggle the "Enabled" switch on the main view.
6. You are all set up!

#### Per App Settings:

Sometimes you may encounter an app that still works with apple's built in APNS (like WA for legacy iOS, or eBaY). This menu lets you select if you want an app to use Skyglow Notifications, or Apple's notification service. For an app to show up on this list, it must

1. be an app that can send notifications
2. tried to register for notifications since Skyglow Notifcations was installed

## Features

The best part of this daemon is its usage simplicity, it can be easily adapted to work with one or multiple services, allowing users to have notifications in their old iDevices easily, see documentation for an in depth review.

## Building

The whole project builds with [theos](https://theos.dev/docs/installation) on a macOS host. Every third party library is under `libraries/` so nothing else has to be installed other than the SDK for the target you want.

`BuildConfig.mk` picks the target from the make invocation:

| Target                                     | Command                                                     | SDK in `$THEOS/sdks`                        | Produces                                                                                                                     |
| ------------------------------------------ | ----------------------------------------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| iOS 4.0+, rootful (armv7 / armv7s / arm64) | `make package FINALPACKAGE=1`                               | `iPhoneOS7.0.sdk`                           | `packages/*.deb` daemon, `sgnctl`, preference bundle, SpringBoard tweak                                                      |
| iOS 15+, rootless (arm64 / arm64e)         | `make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless` | `iPhoneOS16.5.sdk`                          | same, rootless layout                                                                                                        |
| macOS 10.8+ (x86_64) / 11+ (arm64)         | `make macpkg PLATFORM=OSX FINALPACKAGE=1`                   | the macOS SDK shipped with Xcode (`latest`) | `packages/com.skyglow.snd-<arch>-<version>.pkg` — daemon + `sgnctl` with the post-install script that loads the LaunchDaemon |

Notes:

- macOS builds for the host architecture by default, pass `MACOS_ARCH=x86_64` or `MACOS_ARCH=arm64` to cross-build. `make package PLATFORM=OSX` also works but yields theos's bare `.pkg` without the post-install script (theos pls add support :)).
- Logging toggles are compile time defaults: `SG_DAEMON_FILE_LOGGING` (1), `SG_DAEMON_CONSOLE_LOGGING` (0), `SG_DAEMON_TTY_LOGGING` (1), e.g. `make package PLATFORM=OSX SG_DAEMON_CONSOLE_LOGGING=1`.
- Host-side unit tests for the pure C parts: `sh Skyglow-Notifications-Daemon/tests/run.sh`.
- `make -f tools/Makefile` builds a standalone `build/sgnctl` for the Mac host without theos.

## Documentation

[Protocol Documentation](https://cydia.skyglow.es/tweaks/Notifications/Documentation/protocol.html) & [Client Specification](https://cydia.skyglow.es/tweaks/Notifications/Documentation/client.html)

## Contributors

- [**ObscureMosquito:**](https://github.com/ObscureMosquito) ObscureMosquito, Requis, or otherwise me, created the tweak and architecture originally, and actively maintain the tweak.

- [**Preloading**:](https://github.com/Preloading) Apart from creating the server, completely revamped the comunication stack and protocol, added features like app registration and multi server support and improved security and reliability.
