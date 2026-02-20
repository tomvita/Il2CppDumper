using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Il2CppDumper
{
    internal static class RvaIndexBuilder
    {
        private const ushort FormatVersionV3 = 3;
        private const ushort CurrentFormatVersion = FormatVersionV3;
        private const int DefaultMaxRecordsPerBlock = 1024;
        private static readonly Regex MethodRvaRegex = new(@"^\t// RVA:\s*0x([0-9A-Fa-f]+)\b", RegexOptions.Compiled);
        private static readonly Regex GenericInstMethodRvaRegex = new(@"^\t\|-RVA:\s*0x([0-9A-Fa-f]+)\b", RegexOptions.Compiled);

        private readonly struct RvaLine
        {
            public readonly ulong Rva;
            public readonly uint DumpOffset;

            public RvaLine(ulong rva, uint dumpOffset)
            {
                Rva = rva;
                DumpOffset = dumpOffset;
            }
        }

        private sealed class Block
        {
            public ulong StartRva;
            public uint StartDumpOffset;
            public List<(uint AddrDelta, uint DumpOffset)> Records = new();
        }

        private readonly struct Index1Entry
        {
            public readonly ulong StartRva;
            public readonly ulong Index2Offset;
            public readonly uint Index2Size;

            public Index1Entry(ulong startRva, ulong index2Offset, uint index2Size)
            {
                StartRva = startRva;
                Index2Offset = index2Offset;
                Index2Size = index2Size;
            }
        }

        public static void Build(string dumpPath, string index1Path, string index2Path, int maxRecordsPerBlock = DefaultMaxRecordsPerBlock)
        {
            if (maxRecordsPerBlock <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxRecordsPerBlock));
            }

            var records = ParseRvaLines(dumpPath, out var totalDumpLines);
            if (records.Count == 0)
            {
                WriteEmptyIndexes(index1Path, index2Path, totalDumpLines);
                return;
            }

            records.Sort((a, b) =>
            {
                var cmp = a.Rva.CompareTo(b.Rva);
                if (cmp != 0) return cmp;
                return a.DumpOffset.CompareTo(b.DumpOffset);
            });

            var blocks = BuildBlocks(records, maxRecordsPerBlock);
            WriteIndexes(index1Path, index2Path, blocks, totalDumpLines);
        }

        private static List<RvaLine> ParseRvaLines(string dumpPath, out uint totalDumpLines)
        {
            var records = new List<RvaLine>(16384);
            uint lineNo = 0;
            uint lineStartOffset = 0;
            var lineBytes = new List<byte>(256);

            using var fs = new FileStream(dumpPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            int currentByte;
            while ((currentByte = fs.ReadByte()) >= 0)
            {
                if (currentByte == (byte)'\n')
                {
                    ProcessLine(lineBytes, lineStartOffset, ref lineNo, records);
                    lineStartOffset = ToDumpOffset(fs.Position);
                    lineBytes.Clear();
                }
                else
                {
                    lineBytes.Add((byte)currentByte);
                }
            }

            if (lineBytes.Count > 0)
            {
                ProcessLine(lineBytes, lineStartOffset, ref lineNo, records);
            }

            totalDumpLines = lineNo;
            return records;
        }

        private static void ProcessLine(List<byte> lineBytes, uint lineStartOffset, ref uint lineNo, List<RvaLine> records)
        {
            lineNo++;
            var lineLength = lineBytes.Count;
            if (lineLength > 0 && lineBytes[lineLength - 1] == (byte)'\r')
            {
                lineLength--;
            }

            var line = Encoding.UTF8.GetString(lineBytes.ToArray(), 0, lineLength);
            Match match = MethodRvaRegex.Match(line);
            if (!match.Success)
            {
                match = GenericInstMethodRvaRegex.Match(line);
            }
            if (!match.Success || match.Groups.Count < 2)
            {
                return;
            }
            if (ulong.TryParse(match.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var rva))
            {
                records.Add(new RvaLine(rva, lineStartOffset));
            }
        }

        private static uint ToDumpOffset(long position)
        {
            if (position < 0 || (ulong)position > uint.MaxValue)
            {
                throw new InvalidDataException("dump.cs is larger than supported 32-bit offset range");
            }
            return (uint)position;
        }

        private static List<Block> BuildBlocks(List<RvaLine> records, int maxRecordsPerBlock)
        {
            var blocks = new List<Block>();
            int i = 0;
            while (i < records.Count)
            {
                var first = records[i];
                var block = new Block
                {
                    StartRva = first.Rva,
                    StartDumpOffset = first.DumpOffset
                };
                block.Records.Add((0, first.DumpOffset));
                i++;

                var prevRva = first.Rva;
                while (i < records.Count && block.Records.Count < maxRecordsPerBlock)
                {
                    var next = records[i];
                    var delta = next.Rva - prevRva;
                    if (delta > uint.MaxValue)
                    {
                        break;
                    }
                    block.Records.Add(((uint)delta, next.DumpOffset));
                    prevRva = next.Rva;
                    i++;
                }
                blocks.Add(block);
            }
            return blocks;
        }

        private static void WriteIndexes(string index1Path, string index2Path, List<Block> blocks, uint totalDumpLines)
        {
            var index1Entries = new List<Index1Entry>(blocks.Count);
            using (var fs2 = new FileStream(index2Path, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw2 = new BinaryWriter(fs2, Encoding.UTF8, false))
            {
                bw2.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'2' });
                bw2.Write(CurrentFormatVersion);
                bw2.Write((ushort)0);
                bw2.Write((uint)blocks.Count);
                bw2.Write(totalDumpLines);

                foreach (var block in blocks)
                {
                    var blockOffset = (ulong)fs2.Position;
                    bw2.Write(block.StartRva);
                    bw2.Write(block.StartDumpOffset);
                    bw2.Write((uint)block.Records.Count);
                    foreach (var rec in block.Records)
                    {
                        bw2.Write(rec.AddrDelta);
                        bw2.Write(rec.DumpOffset);
                    }
                    var blockSize = (uint)((ulong)fs2.Position - blockOffset);
                    index1Entries.Add(new Index1Entry(block.StartRva, blockOffset, blockSize));
                }
            }

            using var fs1 = new FileStream(index1Path, FileMode.Create, FileAccess.Write, FileShare.None);
            using var bw1 = new BinaryWriter(fs1, Encoding.UTF8, false);
            bw1.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'1' });
            bw1.Write(CurrentFormatVersion);
            bw1.Write((ushort)0);
            bw1.Write((uint)index1Entries.Count);
            foreach (var entry in index1Entries)
            {
                bw1.Write(entry.StartRva);
                bw1.Write(entry.Index2Offset);
                bw1.Write(entry.Index2Size);
                bw1.Write((uint)0);
            }
        }

        private static void WriteEmptyIndexes(string index1Path, string index2Path, uint totalDumpLines)
        {
            using (var fs2 = new FileStream(index2Path, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw2 = new BinaryWriter(fs2, Encoding.UTF8, false))
            {
                bw2.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'2' });
                bw2.Write(CurrentFormatVersion);
                bw2.Write((ushort)0);
                bw2.Write((uint)0);
                bw2.Write(totalDumpLines);
            }

            using var fs1 = new FileStream(index1Path, FileMode.Create, FileAccess.Write, FileShare.None);
            using var bw1 = new BinaryWriter(fs1, Encoding.UTF8, false);
            bw1.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'1' });
            bw1.Write(CurrentFormatVersion);
            bw1.Write((ushort)0);
            bw1.Write((uint)0);
        }
    }
}
