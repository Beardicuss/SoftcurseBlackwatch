using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

var srcPath = args.Length > 0 ? args[0] : @"Softcurse.UI\Assets\logo-Photoroom.png";
var dstPath = args.Length > 1 ? args[1] : @"Softcurse.UI\Assets\app.ico";

Console.WriteLine($"Converting {srcPath} -> {dstPath}");

using var src = new Bitmap(srcPath);
var sizes = new[] { 16, 32, 48, 256 };

using var ms = new MemoryStream();
using var bw = new BinaryWriter(ms);

bw.Write((short)0);
bw.Write((short)1);
bw.Write((short)sizes.Length);

int offset = 6 + sizes.Length * 16;
var imageData = new List<byte[]>();

foreach (var size in sizes)
{
    using var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(bmp))
    {
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.DrawImage(src, 0, 0, size, size);
    }
    using var pngMs = new MemoryStream();
    bmp.Save(pngMs, ImageFormat.Png);
    var data = pngMs.ToArray();
    imageData.Add(data);

    bw.Write((byte)(size < 256 ? size : 0));
    bw.Write((byte)(size < 256 ? size : 0));
    bw.Write((byte)0);
    bw.Write((byte)0);
    bw.Write((short)1);
    bw.Write((short)32);
    bw.Write(data.Length);
    bw.Write(offset);
    offset += data.Length;
}

foreach (var data in imageData)
    bw.Write(data);

File.WriteAllBytes(dstPath, ms.ToArray());
Console.WriteLine($"Done — {sizes.Length} sizes ({string.Join(", ", sizes)}px)");
