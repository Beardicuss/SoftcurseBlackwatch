using System.Windows;
using Softcurse.UI.ViewModels;

namespace Softcurse.UI;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    protected override void OnClosed(EventArgs e)
    {
        (DataContext as MainViewModel)?.Dispose();
        base.OnClosed(e);
    }
}