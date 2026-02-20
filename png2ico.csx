// PNG to ICO converter — C# script
// Creates multi-resolution ICO (16, 32, 48, 256) from a source PNG
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

var srcPath = args.Length > 0 ? args[0] : @"Softcurse.UI\Assets\logo-Photoroom.png";
var dstPath = args.Length > 1 ? args[1] : @"Softcurse.UI\Assets\app.ico";

Console.WriteLine($"Source: {srcPath}");
Console.WriteLine($"Output: {dstPath}");

using var src = new Bitmap(srcPath);
var sizes = new[] { 16, 32, 48, 256 };

using var ms = new MemoryStream();
using var bw = new BinaryWriter(ms);

// ICO header
bw.Write((short)0);      // reserved
bw.Write((short)1);      // type = ICO
bw.Write((short)sizes.Length);

int offset = 6 + sizes.Length * 16; // header + directory entries
var imageData = new List<byte[]>();

foreach (var size in sizes)
{
    using var bmp = new Bitmap(size, size, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(bmp))
    {
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.SmoothingMode = SmoothingMode.HighQuality;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.DrawImage(src, 0, 0, size, size);
    }

    using var pngMs = new MemoryStream();
    bmp.Save(pngMs, ImageFormat.Png);
    var data = pngMs.ToArray();
    imageData.Add(data);

    // Directory entry
    bw.Write((byte)(size < 256 ? size : 0));  // width
    bw.Write((byte)(size < 256 ? size : 0));  // height
    bw.Write((byte)0);    // color palette
    bw.Write((byte)0);    // reserved
    bw.Write((short)1);   // color planes
    bw.Write((short)32);  // bits per pixel
    bw.Write(data.Length); // image data size
    bw.Write(offset);     // offset
    offset += data.Length;
}

foreach (var data in imageData)
    bw.Write(data);

File.WriteAllBytes(dstPath, ms.ToArray());
Console.WriteLine($"Created {dstPath} with {sizes.Length} sizes: {string.Join(", ", sizes)}px");
