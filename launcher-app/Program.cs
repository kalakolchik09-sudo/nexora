using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using CmlLib.Core;
using CmlLib.Core.Auth;
using CmlLib.Core.Auth.Microsoft;
using CmlLib.Core.ProcessBuilder;
using CmlLib.Core.ModLoaders.FabricMC;

namespace NexoraLauncher;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        var app = new Application
        {
            ShutdownMode = ShutdownMode.OnMainWindowClose
        };
        app.Run(new LauncherWindow());
    }
}

internal sealed class LauncherWindow : Window
{
    private readonly Uri _siteBaseUri = new(Environment.GetEnvironmentVariable("NEXORA_SITE_URL") ?? "https://nexora-production-9548.up.railway.app");
    private string LauncherUrl => new Uri(_siteBaseUri, "/launcher").AbsoluteUri;
    private readonly WebView2 _webView = new();
    private readonly JELoginHandler _minecraftLogin = JELoginHandlerBuilder.BuildDefault();
    private MSession? _minecraftSession;
    private bool _launchInProgress;
    private bool _isMaximized;
    private const double WindowCornerRadius = 18;

    public LauncherWindow()
    {
        Title = "NEXORA Launcher";
        // Leave enough room for the prototype's 24px page padding and 720px launcher.
        Width = 1240;
        Height = 850;
        MinWidth = 820;
        MinHeight = 600;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(9, 11, 23));
        Content = _webView;
        SourceInitialized += (_, _) => ApplyRoundedWindowRegion();
        SizeChanged += (_, _) => ApplyRoundedWindowRegion();
        Loaded += OnLoaded;
    }

    private void ApplyRoundedWindowRegion()
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        if (hwnd == IntPtr.Zero || !GetWindowRect(hwnd, out var rect)) return;

        var scale = VisualTreeHelper.GetDpi(this).DpiScaleX;
        var radius = Math.Max(1, (int)Math.Round(WindowCornerRadius * scale));
        var region = CreateRoundRectRgn(0, 0, rect.Right - rect.Left + 1, rect.Bottom - rect.Top + 1, radius * 2, radius * 2);
        if (SetWindowRgn(hwnd, region, true) == 0) DeleteObject(region);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hwnd, out NativeRect rect);

    [DllImport("gdi32.dll", SetLastError = true)]
    private static extern IntPtr CreateRoundRectRgn(int left, int top, int right, int bottom, int widthEllipse, int heightEllipse);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern int SetWindowRgn(IntPtr hwnd, IntPtr region, [MarshalAs(UnmanagedType.Bool)] bool redraw);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(IntPtr objectHandle);

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            _webView.DefaultBackgroundColor = System.Drawing.Color.FromArgb(255, 9, 11, 23);
            var dataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NEXORA Launcher",
                "WebView2");
            Directory.CreateDirectory(dataFolder);
            var environment = await CoreWebView2Environment.CreateAsync(null, dataFolder);
            await _webView.EnsureCoreWebView2Async(environment);

            var core = _webView.CoreWebView2;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.IsZoomControlEnabled = false;
            core.WebMessageReceived += OnWebMessageReceived;
            core.NavigationStarting += (_, args) => Log($"NavigationStarting: {args.Uri}");
            core.NavigationCompleted += async (_, args) =>
            {
                Log($"NavigationCompleted: success={args.IsSuccess}, error={args.WebErrorStatus}");
                if (!args.IsSuccess)
                {
                    MessageBox.Show(this,
                        "Не удалось подключиться к серверу NEXORA. Проверь интернет-соединение и попробуй открыть лаунчер позже.\n\n" + args.WebErrorStatus,
                        "NEXORA Launcher", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                if (args.IsSuccess)
                {
                    var state = await core.ExecuteScriptAsync(
                        "JSON.stringify({title:document.title,launcher:!!document.querySelector('.launcher'),width:document.querySelector('.launcher')?.getBoundingClientRect().width,height:document.querySelector('.launcher')?.getBoundingClientRect().height,borderRadius:getComputedStyle(document.querySelector('.launcher')).borderRadius,bodyPadding:getComputedStyle(document.body).padding,scrollbarWidth:getComputedStyle(document.querySelector('.content')).scrollbarWidth,moleculeAnimation:getComputedStyle(document.querySelector('.atom-orbit')).animationName})");
                    Log($"Rendered UI: {state}");
                }
            };
            core.ProcessFailed += (_, args) => Log($"WebView2 ProcessFailed: {args.ProcessFailedKind}");
            core.NavigationStarting += (_, args) =>
            {
                if (!Uri.TryCreate(args.Uri, UriKind.Absolute, out var uri) ||
                    !uri.Scheme.Equals(_siteBaseUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
                    !uri.Host.Equals(_siteBaseUri.Host, StringComparison.OrdinalIgnoreCase) ||
                    uri.Port != _siteBaseUri.Port)
                    args.Cancel = true;
            };

            await core.AddScriptToExecuteOnDocumentCreatedAsync("""
                (() => {
                  const send = (message) => window.chrome.webview.postMessage(message);
                  window.addEventListener('error', event => send('runtime-error:' + (event.message || 'unknown')));
                  window.addEventListener('unhandledrejection', event => send('runtime-error:' + String(event.reason)));
                  document.addEventListener('DOMContentLoaded', () => {
                    document.querySelector('[data-window-action="minimize"]')?.addEventListener('click', () => send('minimize'));
                    document.querySelector('[data-window-action="maximize"]')?.addEventListener('click', () => send('maximize'));
                    document.querySelector('[data-window-action="close"]')?.addEventListener('click', () => send('close'));
                    document.querySelector('.topbar')?.addEventListener('mousedown', event => {
                      if (!event.target.closest('button')) send('drag');
                    });
                  });
                })();
                """);

            core.Navigate(LauncherUrl);
        }
        catch (Exception error)
        {
            MessageBox.Show(
                this,
                "Не удалось открыть интерфейс лаунчера. Убедись, что установлен Microsoft Edge WebView2 Runtime.\n\n" + error.Message,
                "NEXORA Launcher",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Close();
        }
    }

    private void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        var command = e.TryGetWebMessageAsString();
        if (command.StartsWith("runtime-error:", StringComparison.Ordinal))
        {
            Log(command);
            return;
        }
        if (command.StartsWith("launch:", StringComparison.Ordinal))
        {
            var version = command["launch:".Length..];
            _ = LaunchMinecraftAsync(version);
            return;
        }
        switch (command)
        {
            case "close":
                Close();
                break;
            case "minimize":
                WindowState = WindowState.Minimized;
                break;
            case "maximize":
                _isMaximized = !_isMaximized;
                WindowState = _isMaximized ? WindowState.Maximized : WindowState.Normal;
                break;
            case "drag":
                try { DragMove(); }
                catch (InvalidOperationException) { }
                break;
        }
    }

    private async Task LaunchMinecraftAsync(string version)
    {
        if (_launchInProgress) return;
        if (version is not ("1.16.5" or "1.21.11"))
        {
            SendLauncherStatus("Выбрана неизвестная версия игры.", isError: true);
            return;
        }

        _launchInProgress = true;
        try
        {
            SendLauncherStatus("Выполняется вход в Microsoft. Войди в аккаунт с лицензией Minecraft: Java Edition.");
            _minecraftSession ??= await _minecraftLogin.Authenticate();

            var gamePath = new MinecraftPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NEXORA Launcher", "Minecraft"));
            var launcher = new MinecraftLauncher(gamePath);
            launcher.FileProgressChanged += (_, progress) =>
                Dispatcher.BeginInvoke(() => SendLauncherStatus($"Загрузка Minecraft {version}: {progress.ProgressedTasks}/{progress.TotalTasks}"));

            SendLauncherStatus($"Установка Fabric для Minecraft {version} и Java Runtime…");
            var fabric = new FabricInstaller(new HttpClient());
            var fabricVersion = await fabric.Install(version, gamePath);
            await launcher.InstallAsync(fabricVersion);

            var process = await launcher.BuildProcessAsync(fabricVersion, new MLaunchOption
            {
                Session = _minecraftSession,
                MaximumRamMb = Math.Clamp((int)(GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / 1024 / 1024 / 3), 2048, 8192)
            });
            process.Start();
            _ = Dispatcher.BeginInvoke(() => WindowState = WindowState.Minimized);
            SendLauncherStatus($"Minecraft {version} запущен.");
        }
        catch (Exception error)
        {
            Log($"Minecraft launch failed ({version}): {error}");
            SendLauncherStatus("Не удалось запустить игру: " + error.Message, isError: true);
        }
        finally
        {
            _launchInProgress = false;
        }
    }

    private void SendLauncherStatus(string message, bool isError = false)
    {
        if (_webView.CoreWebView2 is null) return;
        try { _webView.CoreWebView2.PostWebMessageAsJson(System.Text.Json.JsonSerializer.Serialize(new { type = "minecraft-status", message, isError })); }
        catch { }
    }

    private static void Log(string message)
    {
        try
        {
            var logFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "NEXORA Launcher");
            Directory.CreateDirectory(logFolder);
            File.AppendAllText(Path.Combine(logFolder, "launcher.log"), $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}");
        }
        catch { }
    }
}
