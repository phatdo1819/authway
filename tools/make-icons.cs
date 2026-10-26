using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;

// make-icons.exe <folder>: the icons of assets\, a white keyhole on a rounded square, the same drawing as the
// icon of the login page; build.rs embeds them in the exe. Also the pictures of the dialogs of the MSI package.
static class MakeIcons
{
    static readonly Color Brand = Color.FromArgb(0x03, 0x69, 0xa1);
    static readonly Color Idle = Color.FromArgb(0x64, 0x74, 0x8b);
    static readonly Color Attention = Color.FromArgb(0xd9, 0x77, 0x06);
    static readonly Color Refused = Color.FromArgb(0xb9, 0x1c, 0x1c);

    // the sizes of the tray at 100% to 300%, and of the windows
    static readonly int[] TraySizes = { 16, 20, 24, 32, 40, 48 };
    static readonly int[] AppSizes = { 16, 20, 24, 32, 40, 48, 64, 256 };

    static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("usage: make-icons.exe <folder>");
            return 2;
        }
        Write(Path.Combine(args[0], "app.ico"), Brand, AppSizes);
        Write(Path.Combine(args[0], "connected.ico"), Brand, TraySizes);
        Write(Path.Combine(args[0], "idle.ico"), Idle, TraySizes);
        Write(Path.Combine(args[0], "attention.ico"), Attention, TraySizes);
        Write(Path.Combine(args[0], "refused.ico"), Refused, TraySizes);
        WriteInstallerImages(args[0]);
        return 0;
    }

    // At the sizes of WixUI: the welcome and last pages, with the icon on the left; the banner of the other pages,
    // with the icon on the right
    static void WriteInstallerImages(string folder)
    {
        using (var dialog = new Bitmap(493, 312, PixelFormat.Format24bppRgb))
        {
            using (var graphics = Graphics.FromImage(dialog))
            using (var brush = new SolidBrush(Brand))
            using (var icon = Draw(96, Color.White, Brand))
            {
                graphics.Clear(Color.White);
                graphics.FillRectangle(brush, 0, 0, 164, 312);
                graphics.DrawImage(icon, (164 - 96) / 2, 56);
            }
            WriteBmp(Path.Combine(folder, "installer-dialog.bmp"), dialog);
        }
        using (var banner = new Bitmap(493, 58, PixelFormat.Format24bppRgb))
        {
            using (var graphics = Graphics.FromImage(banner))
            using (var icon = Draw(40, Brand, Color.White))
            {
                graphics.Clear(Color.White);
                graphics.DrawImage(icon, 493 - 40 - 12, 9);
            }
            WriteBmp(Path.Combine(folder, "installer-banner.bmp"), banner);
        }
    }

    // A bitmap of 256 colors, the steps from white to the color of the app: every pixel of the pictures is one of
    // them, and the package keeps a third of the size of 24 bits
    static void WriteBmp(string path, Bitmap image)
    {
        int width = image.Width;
        int height = image.Height;
        int stride = (width + 3) / 4 * 4;
        int offset = 14 + 40 + 256 * 4;
        using (var file = File.Create(path))
        {
            var writer = new BinaryWriter(file);
            // BITMAPFILEHEADER
            writer.Write((byte)'B');
            writer.Write((byte)'M');
            writer.Write(offset + stride * height);
            writer.Write(0);
            writer.Write(offset);
            // BITMAPINFOHEADER
            writer.Write(40);
            writer.Write(width);
            writer.Write(height);
            writer.Write((short)1);
            writer.Write((short)8);
            writer.Write(0);
            writer.Write(stride * height);
            writer.Write(2835);
            writer.Write(2835);
            writer.Write(256);
            writer.Write(0);
            for (int i = 0; i < 256; i++)
            {
                writer.Write((byte)(255 + (Brand.B - 255) * i / 255));
                writer.Write((byte)(255 + (Brand.G - 255) * i / 255));
                writer.Write((byte)(255 + (Brand.R - 255) * i / 255));
                writer.Write((byte)0);
            }
            // the rows go from the bottom up; the step of a pixel is how far it is from white
            var row = new byte[stride];
            for (int y = height - 1; y >= 0; y--)
            {
                for (int x = 0; x < width; x++)
                {
                    var pixel = image.GetPixel(x, y);
                    row[x] = (byte)Math.Max(0, Math.Min(255, (int)Math.Round(255.0 * (255 - pixel.R) / (255 - Brand.R))));
                }
                writer.Write(row);
            }
            writer.Flush();
        }
    }

    static void Write(string path, Color color, int[] sizes)
    {
        var images = sizes.Select(size => Draw(size, color, Color.White)).ToList();
        try
        {
            using (var file = File.Create(path))
                WriteIco(file, images);
        }
        finally
        {
            foreach (var image in images)
                image.Dispose();
        }
    }

    // Drawn on a grid of 100 as icon.svg of the login page, with a larger keyhole in the small sizes of the
    // tray, to keep it visible
    static Bitmap Draw(int size, Color background, Color keyhole)
    {
        var bitmap = new Bitmap(size, size, PixelFormat.Format32bppArgb);
        using (var graphics = Graphics.FromImage(bitmap))
        using (var brush = new SolidBrush(background))
        using (var hole = new SolidBrush(keyhole))
        using (var square = RoundedSquare(size, size * 0.18f))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
            graphics.Clear(Color.Transparent);
            graphics.FillPath(brush, square);
            float unit = size / 100f;
            float scale = size <= 24 ? 1.3f : 1f;
            graphics.TranslateTransform(50 * unit, 50 * unit);
            graphics.ScaleTransform(scale, scale);
            graphics.TranslateTransform(-50 * unit, -50 * unit);
            graphics.FillEllipse(hole, 37 * unit, 27 * unit, 26 * unit, 26 * unit);
            graphics.FillPolygon(hole, new[]
            {
                new PointF(45 * unit, 44 * unit), new PointF(40 * unit, 72 * unit),
                new PointF(60 * unit, 72 * unit), new PointF(55 * unit, 44 * unit),
            });
        }
        return bitmap;
    }

    // An .ico file: PNG for 256 pixels, a bitmap with alpha for the smaller sizes
    static void WriteIco(Stream output, IList<Bitmap> images)
    {
        var data = new List<byte[]>();
        foreach (var image in images)
            data.Add(image.Width >= 256 ? Png(image) : Dib(image));
        var writer = new BinaryWriter(output);
        writer.Write((short)0);
        writer.Write((short)1);
        writer.Write((short)images.Count);
        int offset = 6 + 16 * images.Count;
        for (int i = 0; i < images.Count; i++)
        {
            writer.Write((byte)(images[i].Width >= 256 ? 0 : images[i].Width));
            writer.Write((byte)(images[i].Height >= 256 ? 0 : images[i].Height));
            writer.Write((byte)0);
            writer.Write((byte)0);
            writer.Write((short)1);
            writer.Write((short)32);
            writer.Write(data[i].Length);
            writer.Write(offset);
            offset += data[i].Length;
        }
        foreach (var bytes in data)
            writer.Write(bytes);
        writer.Flush();
    }

    static GraphicsPath RoundedSquare(int size, float radius)
    {
        var path = new GraphicsPath();
        float diameter = radius * 2;
        path.AddArc(0, 0, diameter, diameter, 180, 90);
        path.AddArc(size - diameter, 0, diameter, diameter, 270, 90);
        path.AddArc(size - diameter, size - diameter, diameter, diameter, 0, 90);
        path.AddArc(0, size - diameter, diameter, diameter, 90, 90);
        path.CloseFigure();
        return path;
    }

    static byte[] Png(Bitmap image)
    {
        using (var stream = new MemoryStream())
        {
            image.Save(stream, ImageFormat.Png);
            return stream.ToArray();
        }
    }

    static byte[] Dib(Bitmap image)
    {
        int width = image.Width;
        int height = image.Height;
        int maskStride = (width + 31) / 32 * 4;
        var mask = new byte[maskStride * height];
        using (var stream = new MemoryStream())
        {
            var writer = new BinaryWriter(stream);
            // BITMAPINFOHEADER: the height counts the colors and the mask
            writer.Write(40);
            writer.Write(width);
            writer.Write(height * 2);
            writer.Write((short)1);
            writer.Write((short)32);
            writer.Write(0);
            writer.Write(width * height * 4 + mask.Length);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            writer.Write(0);
            // the rows go from the bottom up
            for (int y = height - 1; y >= 0; y--)
            {
                for (int x = 0; x < width; x++)
                {
                    var pixel = image.GetPixel(x, y);
                    writer.Write(pixel.B);
                    writer.Write(pixel.G);
                    writer.Write(pixel.R);
                    writer.Write(pixel.A);
                    if (pixel.A == 0)
                        mask[(height - 1 - y) * maskStride + x / 8] |= (byte)(0x80 >> (x % 8));
                }
            }
            writer.Write(mask);
            writer.Flush();
            return stream.ToArray();
        }
    }
}
