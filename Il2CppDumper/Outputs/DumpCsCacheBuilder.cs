using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Il2CppDumper
{
    internal static class DumpCsCacheBuilder
    {
        private const uint NamespaceIndexMagic = 0x3153494E; // "NIS1"
        private const uint TypeIndexMagic = 0x32595054; // "TYP2"

        private readonly struct TypeInfo
        {
            public readonly ulong Offset;
            public readonly string TypeName;
            public readonly string FullName;
            public readonly string BaseName;
            public readonly string NamespaceName;

            public TypeInfo(ulong offset, string typeName, string fullName, string baseName, string namespaceName)
            {
                Offset = offset;
                TypeName = typeName;
                FullName = fullName;
                BaseName = baseName;
                NamespaceName = namespaceName;
            }
        }

        public static void Build(string dumpPath, string definitionCachePath, string namespaceOffsetsPath, string typeIndexPath)
        {
            if (!File.Exists(dumpPath))
            {
                throw new FileNotFoundException("dump.cs not found", dumpPath);
            }

            var fileInfo = new FileInfo(dumpPath);
            var dumpSize = (ulong)fileInfo.Length;
            var dumpMtime = (ulong)new DateTimeOffset(fileInfo.LastWriteTimeUtc).ToUnixTimeSeconds();

            var definitionOffsets = new Dictionary<string, List<ulong>>(StringComparer.Ordinal);
            var namespaceOffsets = new List<uint>();
            var typeInfos = new List<TypeInfo>();

            string currentNamespace = string.Empty;
            ScanDumpFile(dumpPath, currentNamespace, definitionOffsets, namespaceOffsets, typeInfos);

            foreach (var key in definitionOffsets.Keys.ToList())
            {
                var values = definitionOffsets[key];
                values.Sort();
                definitionOffsets[key] = values.Distinct().ToList();
            }
            namespaceOffsets.Sort();
            namespaceOffsets = namespaceOffsets.Distinct().ToList();
            typeInfos.Sort((a, b) => a.Offset.CompareTo(b.Offset));

            WriteDefinitionCache(definitionCachePath, dumpSize, dumpMtime, definitionOffsets);
            WriteNamespaceOffsets(namespaceOffsetsPath, dumpSize, dumpMtime, namespaceOffsets);
            WriteTypeIndex(typeIndexPath, dumpSize, dumpMtime, typeInfos);
        }

        private static void ScanDumpFile(
            string dumpPath,
            string currentNamespace,
            Dictionary<string, List<ulong>> definitionOffsets,
            List<uint> namespaceOffsets,
            List<TypeInfo> typeInfos)
        {
            using var fs = new FileStream(dumpPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            ulong lineStartOffset = 0;
            var lineBytes = new List<byte>(256);
            int currentByte;
            while ((currentByte = fs.ReadByte()) >= 0)
            {
                if (currentByte == (byte)'\n')
                {
                    ProcessLine(
                        lineBytes,
                        lineStartOffset,
                        ref currentNamespace,
                        definitionOffsets,
                        namespaceOffsets,
                        typeInfos);
                    lineStartOffset = (ulong)fs.Position;
                    lineBytes.Clear();
                }
                else
                {
                    lineBytes.Add((byte)currentByte);
                }
            }

            if (lineBytes.Count > 0)
            {
                ProcessLine(
                    lineBytes,
                    lineStartOffset,
                    ref currentNamespace,
                    definitionOffsets,
                    namespaceOffsets,
                    typeInfos);
            }
        }

        private static void ProcessLine(
            List<byte> lineBytes,
            ulong lineStartOffset,
            ref string currentNamespace,
            Dictionary<string, List<ulong>> definitionOffsets,
            List<uint> namespaceOffsets,
            List<TypeInfo> typeInfos)
        {
            var lineLength = lineBytes.Count;
            if (lineLength > 0 && lineBytes[lineLength - 1] == (byte)'\r')
            {
                lineLength--;
            }

            var line = Encoding.UTF8.GetString(lineBytes.ToArray(), 0, lineLength);
            var trimmed = line.Trim();
            if (trimmed.StartsWith("// Namespace:", StringComparison.Ordinal))
            {
                if (lineStartOffset <= uint.MaxValue)
                {
                    namespaceOffsets.Add((uint)lineStartOffset);
                }
                currentNamespace = trimmed.Substring("// Namespace:".Length).Trim();
            }

            if (TryExtractPublicDefinitionWord(trimmed, out var definitionWord))
            {
                if (!definitionOffsets.TryGetValue(definitionWord, out var offsets))
                {
                    offsets = new List<ulong>();
                    definitionOffsets[definitionWord] = offsets;
                }
                offsets.Add(lineStartOffset);
            }

            if (TryExtractTypeInfo(trimmed, currentNamespace, out var typeName, out var fullName, out var baseName, out var namespaceName))
            {
                typeInfos.Add(new TypeInfo(lineStartOffset, typeName, fullName, baseName, namespaceName));
            }
        }

        private static bool TryExtractPublicDefinitionWord(string line, out string word)
        {
            word = string.Empty;
            if (line.StartsWith("public class ", StringComparison.Ordinal))
            {
                return TryExtractNameToken(line, "public class ".Length, out word);
            }
            if (line.StartsWith("public struct ", StringComparison.Ordinal))
            {
                return TryExtractNameToken(line, "public struct ".Length, out word);
            }
            if (line.StartsWith("public enum ", StringComparison.Ordinal))
            {
                return TryExtractNameToken(line, "public enum ".Length, out word);
            }
            return false;
        }

        private static bool TryExtractTypeInfo(
            string line,
            string namespaceName,
            out string typeName,
            out string fullName,
            out string baseName,
            out string normalizedNamespaceName)
        {
            typeName = string.Empty;
            fullName = string.Empty;
            baseName = string.Empty;
            normalizedNamespaceName = namespaceName ?? string.Empty;

            if (!line.Contains("TypeDefIndex:", StringComparison.Ordinal))
            {
                return false;
            }

            var commentIndex = line.IndexOf("// TypeDefIndex:", StringComparison.Ordinal);
            var header = (commentIndex >= 0 ? line[..commentIndex] : line).Trim();
            if (header.Length == 0)
            {
                return false;
            }

            var keywordMap = new (string Keyword, bool IsStruct, bool IsEnum)[]
            {
                (" class ", false, false),
                (" struct ", true, false),
                (" enum ", false, true),
                (" interface ", false, false)
            };

            var keywordIndex = -1;
            var keywordLength = 0;
            var isStruct = false;
            var isEnum = false;
            foreach (var candidate in keywordMap)
            {
                var idx = header.IndexOf(candidate.Keyword, StringComparison.Ordinal);
                if (idx < 0)
                {
                    continue;
                }
                keywordIndex = idx;
                keywordLength = candidate.Keyword.Length;
                isStruct = candidate.IsStruct;
                isEnum = candidate.IsEnum;
                break;
            }

            if (keywordIndex < 0)
            {
                return false;
            }

            var typeStart = keywordIndex + keywordLength;
            while (typeStart < header.Length && char.IsWhiteSpace(header[typeStart]))
            {
                typeStart++;
            }

            var typeEnd = typeStart;
            while (typeEnd < header.Length && IsNameChar(header[typeEnd]))
            {
                typeEnd++;
            }

            if (typeEnd <= typeStart)
            {
                return false;
            }

            typeName = NormalizeTypeNameForLookup(header[typeStart..typeEnd]);
            if (typeName.Length == 0)
            {
                return false;
            }

            var colonIndex = header.IndexOf(':', typeEnd);
            if (colonIndex >= 0)
            {
                var baseStart = colonIndex + 1;
                while (baseStart < header.Length && char.IsWhiteSpace(header[baseStart]))
                {
                    baseStart++;
                }

                var baseEnd = baseStart;
                while (baseEnd < header.Length && header[baseEnd] != ',' && header[baseEnd] != '{')
                {
                    baseEnd++;
                }

                baseName = NormalizeTypeNameForLookup(header[baseStart..baseEnd]);
            }
            else
            {
                if (isStruct)
                {
                    baseName = "System.ValueType";
                }
                else if (isEnum)
                {
                    baseName = "System.Enum";
                }
            }

            normalizedNamespaceName = normalizedNamespaceName.Trim();
            fullName = normalizedNamespaceName.Length == 0
                ? typeName
                : normalizedNamespaceName + "." + typeName;

            return true;
        }

        private static bool TryExtractNameToken(string value, int start, out string normalized)
        {
            normalized = string.Empty;
            var end = start;
            while (end < value.Length && IsNameChar(value[end]))
            {
                end++;
            }
            if (end <= start)
            {
                return false;
            }

            normalized = NormalizeSymbolWord(value[start..end]);
            return normalized.Length > 0;
        }

        private static bool IsNameChar(char c)
        {
            return char.IsLetterOrDigit(c)
                   || c == '_'
                   || c == '.'
                   || c == ':'
                   || c == '<'
                   || c == '>'
                   || c == '`';
        }

        private static string NormalizeSymbolWord(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            var start = 0;
            while (start < input.Length && !IsNameChar(input[start]))
            {
                start++;
            }

            var end = input.Length;
            while (end > start && !IsNameChar(input[end - 1]))
            {
                end--;
            }

            if (end <= start)
            {
                return string.Empty;
            }

            return input[start..end];
        }

        private static string NormalizeTypeNameForLookup(string name)
        {
            name = name.Trim();
            if (name.Length == 0)
            {
                return string.Empty;
            }

            uint arrayDims = 0;
            while (name.Length >= 2 && name.EndsWith("[]", StringComparison.Ordinal))
            {
                name = name[..^2].Trim();
                arrayDims++;
            }

            name = NormalizeSymbolWord(name);
            if (name.Length == 0)
            {
                return string.Empty;
            }

            if (name.StartsWith("global::", StringComparison.Ordinal))
            {
                name = name["global::".Length..];
            }

            while (name.Length > 0 && (name[^1] == ',' || name[^1] == ';'))
            {
                name = name[..^1];
            }

            name = name.Trim();
            if (name.Length == 0)
            {
                return string.Empty;
            }

            while (arrayDims-- > 0)
            {
                name += "[]";
            }

            return name;
        }

        private static void WriteDefinitionCache(
            string outputPath,
            ulong dumpSize,
            ulong dumpMtime,
            Dictionary<string, List<ulong>> definitionOffsets)
        {
            using var writer = new StreamWriter(
                new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None),
                new UTF8Encoding(false));
            writer.Write("v2\t");
            writer.Write(dumpSize.ToString("X", CultureInfo.InvariantCulture));
            writer.Write('\t');
            writer.Write(dumpMtime.ToString("X", CultureInfo.InvariantCulture));
            writer.Write('\n');

            foreach (var key in definitionOffsets.Keys.OrderBy(x => x, StringComparer.Ordinal))
            {
                foreach (var offset in definitionOffsets[key])
                {
                    writer.Write("D\t");
                    writer.Write(key);
                    writer.Write('\t');
                    writer.Write(offset.ToString("X", CultureInfo.InvariantCulture));
                    writer.Write('\n');
                }
            }
        }

        private static void WriteNamespaceOffsets(
            string outputPath,
            ulong dumpSize,
            ulong dumpMtime,
            List<uint> namespaceOffsets)
        {
            if (dumpSize > uint.MaxValue || dumpMtime > uint.MaxValue)
            {
                return;
            }

            using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var writer = new BinaryWriter(fs, Encoding.UTF8, false);
            writer.Write(NamespaceIndexMagic);
            writer.Write((uint)dumpSize);
            writer.Write((uint)dumpMtime);
            writer.Write((uint)namespaceOffsets.Count);
            foreach (var offset in namespaceOffsets)
            {
                writer.Write(offset);
            }
        }

        private static void WriteTypeIndex(
            string outputPath,
            ulong dumpSize,
            ulong dumpMtime,
            List<TypeInfo> typeInfos)
        {
            if (typeInfos.Count == 0)
            {
                return;
            }
            if (dumpSize > uint.MaxValue || dumpMtime > uint.MaxValue)
            {
                return;
            }

            using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var writer = new BinaryWriter(fs, Encoding.UTF8, false);
            writer.Write(TypeIndexMagic);
            writer.Write((uint)dumpSize);
            writer.Write((uint)dumpMtime);
            writer.Write((uint)typeInfos.Count);
            foreach (var typeInfo in typeInfos)
            {
                writer.Write((uint)Math.Min(typeInfo.Offset, uint.MaxValue));
                WriteLengthPrefixedString(writer, typeInfo.TypeName);
                WriteLengthPrefixedString(writer, typeInfo.FullName);
                WriteLengthPrefixedString(writer, typeInfo.BaseName);
                WriteLengthPrefixedString(writer, typeInfo.NamespaceName);
            }
        }

        private static void WriteLengthPrefixedString(BinaryWriter writer, string value)
        {
            value ??= string.Empty;
            var bytes = Encoding.UTF8.GetBytes(value);
            writer.Write((uint)bytes.Length);
            writer.Write(bytes);
        }
    }
}
