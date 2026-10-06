//! Decoding of the ETW kernel `FileIo` initiation events the FIM attribution
//! tables read (`EVENT_TRACE_FLAG_FILE_IO_INIT`), shared by the Windows ETW
//! backend and its host-side unit tests.
//!
//! Every one of these events runs in the context of the process that asked
//! for the operation, so the event header's pid is the actor. Layouts (MOF,
//! native pointer size `P`, little-endian):
//!
//! ```text
//! FileIo_Create        (64)          IrpPtr P, FileObject P, TTID u32,
//!                                    CreateOptions u32, FileAttributes u32,
//!                                    ShareAccess u32, OpenPath UTF-16
//! FileIo_ReadWrite     (67, 68)      Offset u64, IrpPtr P, FileObject P,
//!                                    FileKey P, TTID u32, IoSize u32, IoFlags u32
//! FileIo_SimpleOp      (65, 66, ...) IrpPtr P, FileObject P, FileKey P, TTID u32
//! FileIo_Info          (69, 70, 71)  IrpPtr P, FileObject P, FileKey P,
//!                                    ExtraInfo P, TTID u32, InfoClass u32
//! FileIo_PathOperation (79, 80, 81)  IrpPtr P, FileObject P, FileKey P,
//!                                    ExtraInfo P, TTID u32, InfoClass u32,
//!                                    FileName UTF-16
//! ```
//!
//! A delete is `SetInformationFile(FileDisposition[Ex]Information)` on an
//! open file object: the kernel logs `FileIo/Delete` (70) with the object and
//! `FileIo/DeletePath` (79) with the object and the file's name. A rename is
//! `FileIo/Rename` (71) with the object (the old name) and `FileIo/RenamePath`
//! (80) whose `FileName` is the NEW name. Measured on Windows Server 2022
//! (Azure runner, 2026-10-06): `git worktree remove --force` and PowerShell
//! `Remove-Item -Recurse` emit one 70 + 79 pair per file and directory, with
//! `InfoClass` 64 (`FileDispositionInformationEx`); `Rename-Item` emits 71 +
//! 80 with `InfoClass` 10 (`FileRenameInformation`). Until then the decoder
//! dropped all four at its opcode check, so no delete or rename ever had an
//! actor on Windows. An open with `FILE_DELETE_ON_CLOSE` deletes without
//! either event: the file goes when the opener's last handle closes.

/// FileIo/Create: a file open or create, with the path.
pub const FILEIO_CREATE: u8 = 64;
/// FileIo/Cleanup: the last handle to a file object closed.
pub const FILEIO_CLEANUP: u8 = 65;
/// FileIo/Close: the file object released.
pub const FILEIO_CLOSE: u8 = 66;
/// FileIo/Write: a write initiated on an open file object.
pub const FILEIO_WRITE: u8 = 68;
/// FileIo/Delete: the delete disposition set on an open file object.
pub const FILEIO_DELETE: u8 = 70;
/// FileIo/Rename: a rename requested on an open file object (its old name).
pub const FILEIO_RENAME: u8 = 71;
/// FileIo/DeletePath: the same request as FileIo/Delete, naming the file.
pub const FILEIO_DELETE_PATH: u8 = 79;
/// FileIo/RenamePath: the same request as FileIo/Rename, naming the file's
/// new name.
pub const FILEIO_RENAME_PATH: u8 = 80;

/// `CreateOptions` carries the NT create disposition in its top byte; these
/// dispositions create or truncate the file, so the open itself is a write
/// even when no FileIo/Write follows.
const FILE_SUPERSEDE: u32 = 0;
const FILE_CREATE: u32 = 2;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
/// `CreateOptions` (low 24 bits) flag: the file is deleted when the last
/// handle to it closes.
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// What one FileIo initiation event did, as far as the attribution tables
/// care. Paths are as the kernel spelled them (NT object paths, usually
/// `\Device\HarddiskVolumeN\...`); callers canonicalize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileIoAction {
    /// An open of `path` through `file_object`.
    Open {
        file_object: Option<u64>,
        path: String,
        /// The disposition creates or truncates the file.
        writes: bool,
        /// `FILE_DELETE_ON_CLOSE`: the opener deletes the file.
        deletes_on_close: bool,
    },
    /// A write through an open file object.
    Write { file_object: u64 },
    /// The file object's last handle closed, or the object was released.
    Release { file_object: u64 },
    /// The delete disposition set through an open file object.
    Delete { file_object: u64 },
    /// The delete, naming the file.
    DeletePath {
        file_object: Option<u64>,
        path: String,
    },
    /// A rename through an open file object, which still names the old path.
    Rename { file_object: u64 },
    /// The rename, naming the file's new name.
    RenamePath {
        file_object: Option<u64>,
        new_path: String,
    },
}

/// Whether a FileIo/Create with this `CreateOptions` value creates or
/// truncates the target (a write in itself).
pub fn create_disposition_is_write(create_options: u32) -> bool {
    matches!(
        create_options >> 24,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    )
}

/// Whether a FileIo/Create with this `CreateOptions` value opens the file
/// for deletion on its last close.
pub fn create_options_delete_on_close(create_options: u32) -> bool {
    create_options & FILE_DELETE_ON_CLOSE != 0
}

/// Decode one FileIo initiation payload. `ptr_size` is 8 on a 64-bit
/// kernel (4 when the event header says `EVENT_HEADER_FLAG_32_BIT_HEADER`).
/// `None` for the opcodes the attribution tables do not read and for
/// payloads too short for their layout: an event is unmeasured, never
/// guessed.
pub fn decode(opcode: u8, data: &[u8], ptr_size: usize) -> Option<FileIoAction> {
    let p = if ptr_size == 4 { 4 } else { 8 };
    match opcode {
        FILEIO_CREATE => {
            // IrpPtr, FileObject, TTID, CreateOptions, FileAttributes,
            // ShareAccess, then OpenPath.
            let options_at = 2 * p + 4;
            let path = utf16_cstring(data.get(2 * p + 16..)?);
            if path.is_empty() {
                return None;
            }
            let create_options = read_u32(data, options_at);
            Some(FileIoAction::Open {
                file_object: read_ptr(data, p, p),
                path,
                writes: create_options.is_some_and(create_disposition_is_write),
                deletes_on_close: create_options.is_some_and(create_options_delete_on_close),
            })
        }
        FILEIO_WRITE => Some(FileIoAction::Write {
            // Offset (u64), IrpPtr, then FileObject.
            file_object: read_ptr(data, 8 + p, p)?,
        }),
        FILEIO_CLEANUP | FILEIO_CLOSE => Some(FileIoAction::Release {
            file_object: read_ptr(data, p, p)?,
        }),
        FILEIO_DELETE => Some(FileIoAction::Delete {
            file_object: info_file_object(data, p)?,
        }),
        FILEIO_RENAME => Some(FileIoAction::Rename {
            file_object: info_file_object(data, p)?,
        }),
        FILEIO_DELETE_PATH => {
            let path = path_operation_name(data, p)?;
            Some(FileIoAction::DeletePath {
                file_object: read_ptr(data, p, p),
                path,
            })
        }
        FILEIO_RENAME_PATH => {
            let new_path = path_operation_name(data, p)?;
            Some(FileIoAction::RenamePath {
                file_object: read_ptr(data, p, p),
                new_path,
            })
        }
        _ => None,
    }
}

/// `FileObject` of a FileIo_Info payload, once the payload is long enough to
/// be one (through `InfoClass`).
fn info_file_object(data: &[u8], p: usize) -> Option<u64> {
    if data.len() < 4 * p + 8 {
        return None;
    }
    read_ptr(data, p, p)
}

/// `FileName` of a FileIo_PathOperation payload, `None` when empty.
fn path_operation_name(data: &[u8], p: usize) -> Option<String> {
    let name = utf16_cstring(data.get(4 * p + 8..)?);
    (!name.is_empty()).then_some(name)
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_ptr(data: &[u8], off: usize, ptr: usize) -> Option<u64> {
    let b = data.get(off..off + ptr)?;
    Some(if ptr == 8 {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
    })
}

/// A NUL-terminated (or buffer-terminated) UTF-16LE string.
fn utf16_cstring(bytes: &[u8]) -> String {
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FO: u64 = 0xffff_c283_a766_1150;
    const IRP: u64 = 0xffff_c283_ac0d_8b88;
    const KEY: u64 = 0xffff_8d03_37a1_73b0;

    fn ptr(v: &mut Vec<u8>, val: u64, p: usize) {
        if p == 8 {
            v.extend_from_slice(&val.to_le_bytes());
        } else {
            v.extend_from_slice(&(val as u32).to_le_bytes());
        }
    }

    fn wide(v: &mut Vec<u8>, s: &str) {
        for ch in s.encode_utf16().chain(std::iter::once(0)) {
            v.extend_from_slice(&ch.to_le_bytes());
        }
    }

    fn info(p: usize, extra: u64, info_class: u32) -> Vec<u8> {
        let mut v = Vec::new();
        ptr(&mut v, IRP, p);
        ptr(&mut v, FO, p);
        ptr(&mut v, KEY, p);
        ptr(&mut v, extra, p);
        v.extend_from_slice(&0x33f4u32.to_le_bytes()); // TTID
        v.extend_from_slice(&info_class.to_le_bytes());
        v
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The FileIo/Delete and FileIo/DeletePath that `git worktree remove
    /// --force` emitted for a worktree's `.git` file on the Azure runner
    /// (2026-10-06), byte for byte: the delete names the file through the
    /// file object, the path operation names it outright.
    #[test]
    fn a_delete_measured_on_windows_decodes_to_its_file_object_and_path() {
        let delete =
            hex("181a8da383c2ffffa047229e83c2ffff80613330038dffff0100000000000000f433000040000000");
        assert_eq!(
            decode(FILEIO_DELETE, &delete, 8),
            Some(FileIoAction::Delete {
                file_object: 0xffff_c283_9e22_47a0
            })
        );
        let name = r"\Device\HarddiskVolume4\Users\edamame\AppData\Local\Temp\probe\wt\.git";
        let mut delete_path =
            hex("181a8da383c2ffffa047229e83c2ffff80613330038dffff0000000000000000f433000040000000");
        wide(&mut delete_path, name);
        assert_eq!(
            decode(FILEIO_DELETE_PATH, &delete_path, 8),
            Some(FileIoAction::DeletePath {
                file_object: Some(0xffff_c283_9e22_47a0),
                path: name.to_string(),
            })
        );
    }

    /// FileIo/RenamePath carries the name the file is GIVEN; the old name is
    /// the file object's (PowerShell `Rename-Item a.txt b.txt`, measured).
    #[test]
    fn a_rename_path_names_the_new_name() {
        let mut v = info(8, 0, 10);
        wide(&mut v, r"\Device\HarddiskVolume4\probe\ps\b.txt");
        assert_eq!(
            decode(FILEIO_RENAME_PATH, &v, 8),
            Some(FileIoAction::RenamePath {
                file_object: Some(FO),
                new_path: r"\Device\HarddiskVolume4\probe\ps\b.txt".to_string(),
            })
        );
        assert_eq!(
            decode(FILEIO_RENAME, &info(8, 0, 10), 8),
            Some(FileIoAction::Rename { file_object: FO })
        );
    }

    #[test]
    fn the_32_bit_layouts_are_read_with_4_byte_pointers() {
        assert_eq!(
            decode(FILEIO_DELETE, &info(4, 1, 13), 4),
            Some(FileIoAction::Delete {
                file_object: FO as u32 as u64
            })
        );
        let mut v = info(4, 0, 13);
        wide(&mut v, r"\Device\HarddiskVolume1\x.txt");
        assert_eq!(
            decode(FILEIO_DELETE_PATH, &v, 4),
            Some(FileIoAction::DeletePath {
                file_object: Some(FO as u32 as u64),
                path: r"\Device\HarddiskVolume1\x.txt".to_string(),
            })
        );
    }

    fn create(p: usize, options: u32, path: &str) -> Vec<u8> {
        let mut v = Vec::new();
        ptr(&mut v, IRP, p);
        ptr(&mut v, FO, p);
        v.extend_from_slice(&0x1234u32.to_le_bytes()); // TTID
        v.extend_from_slice(&options.to_le_bytes());
        v.extend_from_slice(&0x80u32.to_le_bytes()); // FileAttributes
        v.extend_from_slice(&7u32.to_le_bytes()); // ShareAccess
        wide(&mut v, path);
        v
    }

    /// The create dispositions and `FILE_DELETE_ON_CLOSE`, as the runner's
    /// git and PowerShell sent them: `0x01204000` opens a directory to
    /// delete it (the delete is the later FileIo/Delete, not the open),
    /// `0x02204021` creates one.
    #[test]
    fn an_open_says_whether_it_writes_or_deletes_on_close() {
        let path = r"\Device\HarddiskVolume4\probe\wt\tests";
        assert_eq!(
            decode(FILEIO_CREATE, &create(8, 0x0120_4000, path), 8),
            Some(FileIoAction::Open {
                file_object: Some(FO),
                path: path.to_string(),
                writes: false,
                deletes_on_close: false,
            })
        );
        assert_eq!(
            decode(FILEIO_CREATE, &create(8, 0x0220_4021, path), 8),
            Some(FileIoAction::Open {
                file_object: Some(FO),
                path: path.to_string(),
                writes: true,
                deletes_on_close: false,
            })
        );
        // FILE_OVERWRITE_IF | FILE_DELETE_ON_CLOSE: a temp file the opener
        // writes and deletes when it lets go.
        assert_eq!(
            decode(FILEIO_CREATE, &create(8, 0x0500_1020, path), 8),
            Some(FileIoAction::Open {
                file_object: Some(FO),
                path: path.to_string(),
                writes: true,
                deletes_on_close: true,
            })
        );
        assert_eq!(
            decode(FILEIO_CREATE, &create(4, 0x0100_1000, path), 4),
            Some(FileIoAction::Open {
                file_object: Some(FO as u32 as u64),
                path: path.to_string(),
                writes: false,
                deletes_on_close: true,
            })
        );
    }

    #[test]
    fn writes_and_releases_name_their_file_object() {
        let mut rw = Vec::new();
        rw.extend_from_slice(&0u64.to_le_bytes()); // Offset
        ptr(&mut rw, IRP, 8);
        ptr(&mut rw, FO, 8);
        ptr(&mut rw, KEY, 8);
        assert_eq!(
            decode(FILEIO_WRITE, &rw, 8),
            Some(FileIoAction::Write { file_object: FO })
        );
        let mut simple = Vec::new();
        ptr(&mut simple, IRP, 8);
        ptr(&mut simple, FO, 8);
        for opcode in [FILEIO_CLEANUP, FILEIO_CLOSE] {
            assert_eq!(
                decode(opcode, &simple, 8),
                Some(FileIoAction::Release { file_object: FO })
            );
        }
    }

    /// Truncated payloads and empty names are unmeasured, and the opcodes
    /// the tables do not read (SetInfo 69, QueryInfo 74, DirEnum 72, ...)
    /// decode to nothing.
    #[test]
    fn short_payloads_empty_names_and_other_opcodes_decode_to_nothing() {
        assert_eq!(decode(FILEIO_DELETE, &info(8, 1, 64)[..39], 8), None);
        assert_eq!(decode(FILEIO_DELETE_PATH, &info(8, 0, 64), 8), None);
        let mut empty_name = info(8, 0, 64);
        wide(&mut empty_name, "");
        assert_eq!(decode(FILEIO_DELETE_PATH, &empty_name, 8), None);
        assert_eq!(decode(FILEIO_CREATE, &create(8, 0, "")[..32], 8), None);
        assert_eq!(decode(FILEIO_WRITE, &[0u8; 20], 8), None);
        for opcode in [67u8, 69, 72, 74, 75, 81] {
            assert_eq!(decode(opcode, &info(8, 0, 4), 8), None, "opcode {opcode}");
        }
    }
}
