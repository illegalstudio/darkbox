use crate::model::{Failure, Limits, Result};
use crate::paths::{self, Nodes};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

pub(crate) struct Directory {
    pub names: Vec<String>,
    pub nodes: Nodes,
}

fn u16_at(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}
fn u32_at(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}
fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_at<const N: usize>(file: &mut File, offset: u64) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut bytes))
        .map_err(crate::read_failure)?;
    Ok(bytes)
}

pub(crate) fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(Failure::limit("Processing time limit exceeded"))
    } else {
        Ok(())
    }
}

// Inspect central records before the ZIP library allocates its entry index.
// This also detects duplicate names that a library's name map could hide.
pub(crate) fn preflight(
    file: &mut File,
    length: u64,
    limits: &Limits,
    deadline: Instant,
) -> Result<Directory> {
    if length < 22 {
        return Err(Failure::invalid(
            "zip.truncated",
            "A complete ZIP end record is required",
        ));
    }
    let tail_len = length.min(65_557) as usize;
    let mut tail = vec![0; tail_len];
    file.seek(SeekFrom::Start(length - tail_len as u64))
        .and_then(|_| file.read_exact(&mut tail))
        .map_err(crate::read_failure)?;
    let end = (0..=tail_len - 22)
        .rev()
        .find(|&pos| {
            tail[pos..pos + 4] == *b"PK\x05\x06"
                && pos + 22 + u16_at(&tail, pos + 20) as usize == tail_len
        })
        .ok_or_else(|| {
            Failure::invalid("zip.end_record", "Missing ZIP end record or trailing data")
        })?;
    let end_offset = length - tail_len as u64 + end as u64;
    let end_record = &tail[end..];
    if u16_at(end_record, 4) != 0
        || u16_at(end_record, 6) != 0
        || u16_at(end_record, 8) != u16_at(end_record, 10)
    {
        return Err(Failure::invalid(
            "zip.split_volume",
            "Split ZIP volumes are forbidden",
        ));
    }
    let mut count = u16_at(end_record, 10) as u64;
    let mut size = u32_at(end_record, 12) as u64;
    let mut offset = u32_at(end_record, 16) as u64;
    let mut records_end = end_offset;
    if count == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff {
        let locator_offset = end_offset
            .checked_sub(20)
            .ok_or_else(|| Failure::invalid("zip.zip64", "Missing ZIP64 locator"))?;
        let locator = read_at::<20>(file, locator_offset)?;
        if locator[..4] != *b"PK\x06\x07" || u32_at(&locator, 4) != 0 || u32_at(&locator, 16) != 1 {
            return Err(Failure::invalid(
                "zip.zip64",
                "Invalid or split ZIP64 locator",
            ));
        }
        let record_offset = u64_at(&locator, 8);
        let record = read_at::<56>(file, record_offset)?;
        let record_size = u64_at(&record, 4);
        if record[..4] != *b"PK\x06\x06"
            || record_size < 44
            || record_offset
                .checked_add(12)
                .and_then(|v| v.checked_add(record_size))
                != Some(locator_offset)
            || u32_at(&record, 16) != 0
            || u32_at(&record, 20) != 0
            || u64_at(&record, 24) != u64_at(&record, 32)
        {
            return Err(Failure::invalid("zip.zip64", "Invalid ZIP64 end record"));
        }
        count = u64_at(&record, 32);
        size = u64_at(&record, 40);
        offset = u64_at(&record, 48);
        records_end = record_offset;
    }
    if count > limits.max_entries as u64 {
        return Err(Failure::limit(
            "ZIP entry count exceeds the configured limit",
        ));
    }
    if offset.checked_add(size) != Some(records_end) || size > length {
        return Err(Failure::invalid(
            "zip.directory",
            "Central directory boundaries do not match the ZIP end records",
        ));
    }
    let mut cursor = offset;
    let mut names = Vec::new();
    let mut nodes = Nodes::new();
    let mut ranges = Vec::new();
    for _ in 0..count {
        check_deadline(deadline)?;
        let header = read_at::<46>(file, cursor)?;
        if header[..4] != *b"PK\x01\x02" {
            return Err(Failure::invalid(
                "zip.directory",
                "Invalid central directory entry",
            ));
        }
        let flags = u16_at(&header, 8);
        let method = u16_at(&header, 10);
        if flags & (1 | 64 | 8192) != 0 {
            return Err(Failure::invalid(
                "zip.encryption",
                "ZIP encryption is forbidden",
            ));
        }
        if !matches!(method, 0 | 8) {
            return Err(Failure::invalid(
                "zip.compression",
                "Only STORE and DEFLATE are supported by Darkbox",
            ));
        }
        let name_len = u16_at(&header, 28) as usize;
        let extra_len = u16_at(&header, 30) as usize;
        let comment_len = u16_at(&header, 32) as u64;
        if name_len == 0 || name_len > 1025 {
            return Err(Failure::invalid(
                "path.invalid",
                "ZIP entry name length is invalid",
            ));
        }
        let next = cursor
            .checked_add(46 + name_len as u64 + extra_len as u64 + comment_len)
            .filter(|end| *end <= records_end)
            .ok_or_else(|| {
                Failure::invalid("zip.directory", "Central entry exceeds directory bounds")
            })?;
        let mut name = vec![0; name_len];
        let mut extra = vec![0; extra_len];
        file.read_exact(&mut name)
            .and_then(|_| file.read_exact(&mut extra))
            .map_err(crate::read_failure)?;
        let name_string = std::str::from_utf8(&name)
            .map_err(|_| {
                Failure::invalid("path.encoding", "ZIP names must use ASCII technical paths")
            })?
            .to_string();
        let directory = name_string.ends_with('/');
        paths::insert(
            &mut nodes,
            name_string.strip_suffix('/').unwrap_or(&name_string),
            directory,
        )?;
        let mut compressed = u32_at(&header, 20) as u64;
        let mut uncompressed = u32_at(&header, 24) as u64;
        let mut local_offset = u32_at(&header, 42) as u64;
        let mut disk = u16_at(&header, 34) as u32;
        let needs_zip64 = compressed == 0xffff_ffff
            || uncompressed == 0xffff_ffff
            || local_offset == 0xffff_ffff
            || disk == 0xffff;
        let mut found_zip64 = false;
        let mut extra_pos = 0;
        while extra_pos < extra.len() {
            if extra_pos + 4 > extra.len() {
                return Err(Failure::invalid("zip.extra", "Truncated ZIP extra field"));
            }
            let tag = u16_at(&extra, extra_pos);
            let field_len = u16_at(&extra, extra_pos + 2) as usize;
            extra_pos += 4;
            let field = extra
                .get(extra_pos..extra_pos + field_len)
                .ok_or_else(|| Failure::invalid("zip.extra", "Truncated ZIP extra field"))?;
            if tag == 1 && needs_zip64 {
                if found_zip64 {
                    return Err(Failure::invalid("zip.zip64", "Duplicate ZIP64 extra field"));
                }
                found_zip64 = true;
                let mut index = 0;
                if uncompressed == 0xffff_ffff {
                    uncompressed = zip64_value(field, index)?;
                    index += 8;
                }
                if compressed == 0xffff_ffff {
                    compressed = zip64_value(field, index)?;
                    index += 8;
                }
                if local_offset == 0xffff_ffff {
                    local_offset = zip64_value(field, index)?;
                    index += 8;
                }
                if disk == 0xffff {
                    if index + 4 > field.len() {
                        return Err(Failure::invalid("zip.zip64", "Truncated ZIP64 disk field"));
                    }
                    disk = u32_at(field, index);
                }
            }
            if tag == 0x7075
                && field.len() >= 5
                && field[0] == 1
                && u32_at(field, 1) == crc32fast::hash(&name)
                && field[5..] != name
            {
                return Err(Failure::invalid(
                    "path.encoding",
                    "Unicode ZIP alias differs from the authoritative technical name",
                ));
            }
            extra_pos += field_len;
        }
        if disk != 0 || (needs_zip64 && !found_zip64) {
            return Err(Failure::invalid(
                "zip.zip64",
                "Missing ZIP64 fields or split volume",
            ));
        }
        let local = read_at::<30>(file, local_offset)?;
        if local[..4] != *b"PK\x03\x04"
            || u16_at(&local, 6) != flags
            || u16_at(&local, 8) != method
            || u16_at(&local, 26) as usize != name.len()
        {
            return Err(Failure::invalid(
                "zip.local_header",
                "Local and central ZIP headers disagree",
            )
            .at(&name_string));
        }
        let mut local_name = vec![0; name.len()];
        file.read_exact(&mut local_name)
            .map_err(crate::read_failure)?;
        if local_name != name {
            return Err(Failure::invalid(
                "zip.local_header",
                "Local and central ZIP names disagree",
            )
            .at(&name_string));
        }
        let mut local_extra = vec![0; u16_at(&local, 28) as usize];
        file.read_exact(&mut local_extra)
            .map_err(crate::read_failure)?;
        let (local_size, local_compressed, local_zip64) =
            local_fields(&local, &local_extra, &name)?;
        if flags & 8 == 0
            && (u32_at(&local, 14) != u32_at(&header, 16)
                || local_size != uncompressed
                || local_compressed != compressed)
        {
            return Err(Failure::invalid(
                "zip.local_header",
                "Local and central CRC or size values disagree",
            )
            .at(&name_string));
        }
        let mut end = local_offset
            .checked_add(30 + name_len as u64 + u16_at(&local, 28) as u64)
            .and_then(|start| start.checked_add(compressed))
            .filter(|end| *end <= offset)
            .ok_or_else(|| {
                Failure::invalid(
                    "zip.local_header",
                    "ZIP data overlaps its central directory",
                )
            })?;
        if flags & 8 != 0 {
            end = descriptor(
                file,
                end,
                offset,
                u32_at(&header, 16),
                compressed,
                uncompressed,
                local_zip64 || found_zip64,
            )?;
        }
        ranges.push((local_offset, end));
        names.push(name_string);
        cursor = next;
    }
    if cursor != records_end {
        return Err(Failure::invalid(
            "zip.directory",
            "Unexpected central directory records",
        ));
    }
    ranges.sort_unstable();
    if ranges.first().is_some_and(|range| range.0 != 0) {
        return Err(Failure::invalid(
            "zip.wrapper",
            "Self-extracting or prefixed ZIP wrappers are forbidden",
        ));
    }
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(Failure::invalid(
            "zip.overlap",
            "ZIP entry data ranges overlap",
        ));
    }
    Ok(Directory { names, nodes })
}

fn zip64_value(field: &[u8], offset: usize) -> Result<u64> {
    if offset + 8 > field.len() {
        Err(Failure::invalid("zip.zip64", "Truncated ZIP64 extra field"))
    } else {
        Ok(u64_at(field, offset))
    }
}

fn local_fields(header: &[u8], extra: &[u8], name: &[u8]) -> Result<(u64, u64, bool)> {
    let mut size = u32_at(header, 22) as u64;
    let mut compressed = u32_at(header, 18) as u64;
    let needs_zip64 = size == 0xffff_ffff || compressed == 0xffff_ffff;
    let mut zip64 = false;
    let mut position = 0;
    while position < extra.len() {
        if position + 4 > extra.len() {
            return Err(Failure::invalid(
                "zip.extra",
                "Truncated local ZIP extra field",
            ));
        }
        let tag = u16_at(extra, position);
        let length = u16_at(extra, position + 2) as usize;
        position += 4;
        let field = extra
            .get(position..position + length)
            .ok_or_else(|| Failure::invalid("zip.extra", "Truncated local ZIP extra field"))?;
        if tag == 1 {
            if zip64 {
                return Err(Failure::invalid(
                    "zip.zip64",
                    "Duplicate local ZIP64 extra field",
                ));
            }
            zip64 = true;
            let mut index = 0;
            if size == 0xffff_ffff {
                size = zip64_value(field, index)?;
                index += 8;
            }
            if compressed == 0xffff_ffff {
                compressed = zip64_value(field, index)?;
            }
        }
        if tag == 0x7075
            && field.len() >= 5
            && field[0] == 1
            && u32_at(field, 1) == crc32fast::hash(name)
            && &field[5..] != name
        {
            return Err(Failure::invalid(
                "path.encoding",
                "Local Unicode ZIP alias differs from the authoritative technical name",
            ));
        }
        position += length;
    }
    if needs_zip64 && !zip64 {
        return Err(Failure::invalid(
            "zip.zip64",
            "Missing local ZIP64 extra fields",
        ));
    }
    Ok((size, compressed, zip64))
}

fn descriptor(
    file: &mut File,
    offset: u64,
    boundary: u64,
    crc: u32,
    compressed: u64,
    size: u64,
    zip64: bool,
) -> Result<u64> {
    let first = read_at::<4>(file, offset)?;
    // An unsigned descriptor can itself have the signature value as its CRC.
    let starts: &[u64] = if first == *b"PK\x07\x08" {
        &[4, 0]
    } else {
        &[0]
    };
    for shift in starts {
        let width = if zip64 { 20 } else { 12 };
        let Some(end) = offset
            .checked_add(*shift + width)
            .filter(|end| *end <= boundary)
        else {
            continue;
        };
        let mut bytes = [0; 20];
        file.seek(SeekFrom::Start(offset + shift))
            .and_then(|_| file.read_exact(&mut bytes[..width as usize]))
            .map_err(crate::read_failure)?;
        let (actual_compressed, actual_size) = if zip64 {
            (u64_at(&bytes, 4), u64_at(&bytes, 12))
        } else {
            (u32_at(&bytes, 4) as u64, u32_at(&bytes, 8) as u64)
        };
        if u32_at(&bytes, 0) == crc && actual_compressed == compressed && actual_size == size {
            return Ok(end);
        }
    }
    Err(Failure::invalid(
        "zip.descriptor",
        "Missing or inconsistent ZIP data descriptor",
    ))
}
