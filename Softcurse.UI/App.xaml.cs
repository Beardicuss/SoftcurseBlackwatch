using System.Windows;

namespace Softcurse.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (e.Args.Contains("--self-test", StringComparer.OrdinalIgnoreCase))
        {
            Shutdown(InstallationSelfTest.Run());
            return;
        }

        MainWindow = new MainWindow();
        MainWindow.Show();
    }
}
