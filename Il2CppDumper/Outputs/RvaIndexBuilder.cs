using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Il2CppDumper
{
    internal static class RvaIndexBuilder
    {
        private const uint FormatVersion = 1;
        private const int DefaultMaxRecordsPerBlock = 1024;
        private static readonly Regex RvaRegex = new(@"RVA:\s*0x([0-9A-Fa-f]+)", RegexOptions.Compiled);

        private readonly struct RvaLine
        {
            public readonly ulong Rva;
            public readonly uint Line;

            public RvaLine(ulong rva, uint line)
            {
                Rva = rva;
                Line = line;
            }
        }

        private sealed class Block
        {
            public ulong StartRva;
            public uint StartLine;
            public List<(uint AddrDelta, uint Line)> Records = new();
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

            var records = ParseRvaLines(dumpPath);
            if (records.Count == 0)
            {
                WriteEmptyIndexes(index1Path, index2Path);
                return;
            }

            records.Sort((a, b) =>
            {
                var cmp = a.Rva.CompareTo(b.Rva);
                if (cmp != 0) return cmp;
                return a.Line.CompareTo(b.Line);
            });

            var blocks = BuildBlocks(records, maxRecordsPerBlock);
            WriteIndexes(index1Path, index2Path, blocks);
        }

        private static List<RvaLine> ParseRvaLines(string dumpPath)
        {
            var records = new List<RvaLine>(16384);
            using var reader = new StreamReader(dumpPath, Encoding.UTF8, true);
            string line;
            uint lineNo = 0;
            while ((line = reader.ReadLine()) != null)
            {
                lineNo++;
                var matches = RvaRegex.Matches(line);
                foreach (Match match in matches)
                {
                    if (!match.Success || match.Groups.Count < 2)
                    {
                        continue;
                    }
                    if (ulong.TryParse(match.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var rva))
                    {
                        records.Add(new RvaLine(rva, lineNo));
                    }
                }
            }
            return records;
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
                    StartLine = first.Line
                };
                block.Records.Add((0, first.Line));
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
                    block.Records.Add(((uint)delta, next.Line));
                    prevRva = next.Rva;
                    i++;
                }
                blocks.Add(block);
            }
            return blocks;
        }

        private static void WriteIndexes(string index1Path, string index2Path, List<Block> blocks)
        {
            var index1Entries = new List<Index1Entry>(blocks.Count);
            using (var fs2 = new FileStream(index2Path, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw2 = new BinaryWriter(fs2, Encoding.UTF8, false))
            {
                bw2.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'2' });
                bw2.Write((ushort)FormatVersion);
                bw2.Write((ushort)0);
                bw2.Write((uint)blocks.Count);

                foreach (var block in blocks)
                {
                    var blockOffset = (ulong)fs2.Position;
                    bw2.Write(block.StartRva);
                    bw2.Write(block.StartLine);
                    bw2.Write((uint)block.Records.Count);
                    foreach (var rec in block.Records)
                    {
                        bw2.Write(rec.AddrDelta);
                        bw2.Write(rec.Line);
                    }
                    var blockSize = (uint)((ulong)fs2.Position - blockOffset);
                    index1Entries.Add(new Index1Entry(block.StartRva, blockOffset, blockSize));
                }
            }

            using var fs1 = new FileStream(index1Path, FileMode.Create, FileAccess.Write, FileShare.None);
            using var bw1 = new BinaryWriter(fs1, Encoding.UTF8, false);
            bw1.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'1' });
            bw1.Write((ushort)FormatVersion);
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

        private static void WriteEmptyIndexes(string index1Path, string index2Path)
        {
            using (var fs2 = new FileStream(index2Path, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var bw2 = new BinaryWriter(fs2, Encoding.UTF8, false))
            {
                bw2.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'2' });
                bw2.Write((ushort)FormatVersion);
                bw2.Write((ushort)0);
                bw2.Write((uint)0);
            }

            using var fs1 = new FileStream(index1Path, FileMode.Create, FileAccess.Write, FileShare.None);
            using var bw1 = new BinaryWriter(fs1, Encoding.UTF8, false);
            bw1.Write(new byte[] { (byte)'I', (byte)'D', (byte)'X', (byte)'1' });
            bw1.Write((ushort)FormatVersion);
            bw1.Write((ushort)0);
            bw1.Write((uint)0);
        }
    }
}
