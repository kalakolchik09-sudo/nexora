# NEXORA Launcher

Windows WPF launcher with WebView2 account UI and Minecraft Java Edition launch support.

- Uses the NEXORA site account and checks the subscription for the selected version before launching.
- Uses Microsoft's Xbox/Minecraft Java sign-in flow. The player must own Minecraft: Java Edition.
- Installs the selected Minecraft version, Fabric Loader, and the Java runtime through CmlLib.
- Does not store the Microsoft password.

Build on Windows with the .NET 8 SDK by running `Build-EXE.cmd`. The app also requires Microsoft Edge WebView2 Runtime and an internet connection.
