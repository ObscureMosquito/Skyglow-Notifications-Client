<div align="center">
<img src="https://github.com/ObscureMosquito/Skyglow-Notifications-Client/blob/main/SGNPreferenceBundle/Resources/icon-settings.png" width=20% height=20%>
<h1>Skyglow Notifications Daemon</h1>
</div>

Simple Cydia Tweak that will open a low power TCP socket and constantly listen for push notifications when deemed appropriate (when network is available as an example), this is made us an alternative to Apple Push Notification Service, adding just a tiny bit of unnoticeable battery overhead, allowing you to host your own free notification server.

## Usage
#### Setting up Skyglow Notifications (only for iOS 6):
1. Download Skyglow Notifications from Cydia, on thru repo https://cydia.skyglow.es or https://cydia.preloading.dev
2. Enter settings
3. Enter into the notification server address the server you would like to use. A list of public servers are available below:
- preloading.dev
> [!TIP]
> If you see a "Port" field, you are using an outdated version of Skyglow Notifications. Please update your version of skyglow notifications from Cydia
4. Hit the register button, after the process, you can see registration details under "Manage Registration"
5. Toggle the "Enabled" switch.
6. You are all set up!

#### Per App Settings:
Sometimes you may encounter an app that still works with apple's built in APNS (like WA for legacy iOS, or eBaY). This menu lets you select if you want an app to use Skyglow Notifications, or Apple's notification service. For an app to show up on this list, it must
1. be an app that can send notifications
2. tried to register for notifications since Skyglow Notifcations was installed 

## Features
The best part of this tweak is it simplicity, it can be easily adapted to work with one or multiple services, allowing users to have notifications in their old iDevices easily, by listening for multiple notification for different apps in the same tweak.

## Documentation
[Protocol Documentation](DOCUMENTATION.md)

## Contributors
- [**ObscureMosquito:**](https://github.com/ObscureMosquito) ObscureMosquito, Requis, or otherwise me, created the tweak and architecture originally, and actively maintain the tweak.


- [**Preloading**:](https://github.com/Preloading) Apart from creating the server, completely revamped the comunication stack and protocol, added features like app registration and multi server support and improved security and reliability.
