using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Softcurse.Shared.Models;

namespace Softcurse.UI.Converters;

// ═══════════════════════════════════════════════
// Value Converters
// ═══════════════════════════════════════════════

public class ThreatLevelToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Critical => new SolidColorBrush(Color.FromRgb(255, 34, 68)),
                ThreatLevel.High => new SolidColorBrush(Color.FromRgb(255, 136, 0)),
                ThreatLevel.Suspicious => new SolidColorBrush(Color.FromRgb(255, 200, 0)),
                ThreatLevel.Low => new SolidColorBrush(Color.FromRgb(0, 136, 255)),
                _ => new SolidColorBrush(Color.FromRgb(0, 255, 136))
            };
        }
        return new SolidColorBrush(Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class ThreatLevelToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatLevel level)
        {
            return level switch
            {
                ThreatLevel.Critical => "■ CRITICAL",
                ThreatLevel.High => "▲ HIGH",
                ThreatLevel.Suspicious => "● SUSPICIOUS",
                ThreatLevel.Low => "○ LOW",
                _ => "✓ SAFE"
            };
        }
        return "?";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class ThreatScoreToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatScore score)
            return $"{score.Total} pts";
        return "0 pts";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class ViewIndexToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int activeView && parameter is string expected && int.TryParse(expected, out int idx))
            return activeView == idx ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class NavTagConverter : IValueConverter
{
    public static readonly NavTagConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int activeView && parameter is string expected && int.TryParse(expected, out int idx))
            return activeView == idx ? "Active" : "";
        return "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class ChartDataToGeometryConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ObservableCollection<float> data && data.Count > 1)
        {
            double width = 400, height = 80;
            double stepX = width / (data.Count - 1);

            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                var startY = height - (data[0] / 100.0 * height);
                ctx.BeginFigure(new Point(0, Math.Clamp(startY, 0, height)), false, false);
                for (int i = 1; i < data.Count; i++)
                {
                    var y = Math.Clamp(height - (data[i] / 100.0 * height), 0, height);
                    ctx.LineTo(new Point(i * stepX, y), true, true);
                }
            }
            geometry.Freeze();
            return geometry;
        }
        return Geometry.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class ChartDataToFillGeometryConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ObservableCollection<float> data && data.Count > 1)
        {
            double width = 400, height = 80;
            double stepX = width / (data.Count - 1);

            var geometry = new StreamGeometry();
            using (var ctx = geometry.Open())
            {
                ctx.BeginFigure(new Point(0, height), true, true);
                for (int i = 0; i < data.Count; i++)
                {
                    var y = Math.Clamp(height - (data[i] / 100.0 * height), 0, height);
                    ctx.LineTo(new Point(i * stepX, y), true, true);
                }
                ctx.LineTo(new Point((data.Count - 1) * stepX, height), true, false);
            }
            geometry.Freeze();
            return geometry;
        }
        return Geometry.Empty;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class LogLevelToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is LogLevel level)
        {
            return level switch
            {
                LogLevel.Critical => new SolidColorBrush(Color.FromRgb(255, 0, 255)),
                LogLevel.Error => new SolidColorBrush(Color.FromRgb(255, 34, 68)),
                LogLevel.Threat => new SolidColorBrush(Color.FromRgb(255, 136, 0)),
                LogLevel.Warning => new SolidColorBrush(Color.FromRgb(255, 200, 0)),
                LogLevel.Info => new SolidColorBrush(Color.FromRgb(0, 255, 255)),
                _ => new SolidColorBrush(Color.FromRgb(110, 170, 170))
            };
        }
        return new SolidColorBrush(Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}

public class BoolToStringConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b && parameter is string options)
        {
            var parts = options.Split('|');
            return b ? parts[0] : (parts.Length > 1 ? parts[1] : "");
        }
        return "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotImplementedException();
}
