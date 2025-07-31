use std::{
    cell::RefCell,
    collections::HashMap,
    io::{Error, ErrorKind, Read, Result, Write},
    sync::{Mutex, OnceLock},
};

static GLOBAL_FS: OnceLock<Mutex<HashMap<String, RefCell<Vec<u8>>>>> = OnceLock::new();

fn get_fs() -> &'static Mutex<HashMap<String, RefCell<Vec<u8>>>> {
    GLOBAL_FS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub struct MemFile {
    name: String,
    cursor: usize,
}

impl MemFile {
    pub fn create<S: AsRef<str>>(name: S) -> Result<Self> {
        let fs = get_fs();
        let mut map = fs.lock().unwrap();
        map.insert(name.as_ref().to_string(), RefCell::new(Vec::new()));
        Ok(Self { name: name.as_ref().to_string(), cursor: 0 })
    }

    pub fn open<S: AsRef<str>>(name: S) -> Result<Self> {
        let fs = get_fs();
        let map = fs.lock().unwrap();
        if map.contains_key(name.as_ref()) {
            Ok(Self { name: name.as_ref().to_string(), cursor: 0 })
        } else {
            Err(Error::new(ErrorKind::NotFound, "File not found"))
        }
    }

    pub fn read<S: AsRef<str>>(name: S) -> Result<Vec<u8>> {
        let fs = get_fs();
        let map = fs.lock().unwrap();
        match map.get(name.as_ref()) {
            Some(cell) => Ok(cell.borrow().clone()),
            None => Err(Error::new(ErrorKind::NotFound, "File not found")),
        }
    }

    pub fn write<S: AsRef<str>>(name: S, data: &[u8]) -> Result<()> {
        let fs = get_fs();
        let mut map = fs.lock().unwrap();
        let cell = map.entry(name.as_ref().to_string()).or_insert_with(|| RefCell::new(Vec::new()));
        let mut content = cell.borrow_mut();
        content.clear();
        content.extend_from_slice(data);
        Ok(())
    }

    pub fn print_fs() {
        let fs = get_fs();
        let map = fs.lock().unwrap();
        println!("MemFS contains {} files:", map.len());
        for (name, cell) in map.iter() {
            let size = cell.borrow().len();
            println!("  {} - {} bytes", name, size);
        }
    }
}

impl Read for MemFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let fs = get_fs();
        let map = fs.lock().unwrap();
        let content =
            map.get(&self.name).ok_or_else(|| Error::new(ErrorKind::NotFound, "File not found"))?;
        let content = content.borrow();
        if self.cursor >= content.len() {
            return Ok(0);
        }
        let len = std::cmp::min(buf.len(), content.len() - self.cursor);
        buf[..len].copy_from_slice(&content[self.cursor..self.cursor + len]);
        self.cursor += len;
        Ok(len)
    }
}

impl Write for MemFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let fs = get_fs();
        let map = fs.lock().unwrap();
        let content_cell =
            map.get(&self.name).ok_or_else(|| Error::new(ErrorKind::NotFound, "File not found"))?;
        let mut content = content_cell.borrow_mut();

        if self.cursor > content.len() {
            content.resize(self.cursor, 0);
        }
        if self.cursor + buf.len() > content.len() {
            content.resize(self.cursor + buf.len(), 0);
        }
        content[self.cursor..self.cursor + buf.len()].copy_from_slice(buf);
        self.cursor += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn test_create_and_write() {
        let mut file = MemFile::create("test_create.txt").unwrap();
        let written = file.write(b"hello").unwrap();
        assert_eq!(written, 5);

        let contents = MemFile::read("test_create.txt").unwrap();
        assert_eq!(contents, b"hello");
    }

    #[test]
    fn test_open_and_read() {
        let mut file = MemFile::create("test_open.txt").unwrap();
        file.write_all(b"rustacean").unwrap();
        file.flush().unwrap();

        let mut file2 = MemFile::open("test_open.txt").unwrap();
        let mut buf = vec![0u8; 9];
        let read_bytes = file2.read(&mut buf).unwrap();
        assert_eq!(read_bytes, 9);
        assert_eq!(&buf, b"rustacean");
    }

    #[test]
    fn test_read_nonexistent_file() {
        let result = MemFile::read("no_such_file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_write_overwrites_existing() {
        let mut file = MemFile::create("test_overwrite.txt").unwrap();
        file.write_all(b"old data").unwrap();

        // Overwrite via static write
        MemFile::write("test_overwrite.txt", b"new data").unwrap();

        let content = MemFile::read("test_overwrite.txt").unwrap();
        assert_eq!(content, b"new data");
    }

    #[test]
    fn test_multiple_reads_and_writes() {
        let mut file = MemFile::create("test_multi.txt").unwrap();

        // Write first chunk
        file.write_all(b"abc").unwrap();
        // Write second chunk
        file.write_all(b"defgh").unwrap();

        file.flush().unwrap();

        // Reset cursor manually for read test
        let mut file2 = MemFile::open("test_multi.txt").unwrap();

        let mut buf = vec![0u8; 8];
        let read_bytes = file2.read(&mut buf).unwrap();
        assert_eq!(read_bytes, 8);
        assert_eq!(&buf[..read_bytes], b"abcdefgh");
    }
    #[test]
    fn test_1gb_read_write() {
        use std::io::{Read, Write};

        // 1GB = 1024 * 1024 * 1024 bytes
        const ONE_GB: usize = 1024 * 1024 * 1024;

        // Create file
        let mut file = MemFile::create("bigfile.bin").expect("create failed");

        // Write 1GB of zero bytes
        let chunk = vec![0u8; 1024 * 1024]; // 1 MB chunk
        let mut written = 0;
        while written < ONE_GB {
            let write_size = std::cmp::min(chunk.len(), ONE_GB - written);
            file.write_all(&chunk[..write_size]).expect("write failed");
            written += write_size;
        }
        file.flush().expect("flush failed");

        // Read back and verify size
        let mut file2 = MemFile::open("bigfile.bin").expect("open failed");
        let mut read_bytes = 0;
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer

        while read_bytes < ONE_GB {
            let read_size = file2.read(&mut buffer).expect("read failed");
            if read_size == 0 {
                break;
            }
            // Check all zeros in the buffer read
            assert!(buffer[..read_size].iter().all(|&b| b == 0));
            read_bytes += read_size;
        }

        assert_eq!(read_bytes, ONE_GB);
    }
}
