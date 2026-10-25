use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use ds_decomp::config::delinks::DelinkFile;

use crate::{config::delinks::DelinksMap, util::path::PathExt};

/// The directory under the build path that holds the copies of objects linked under another name.
const LINK_COPIES_DIR: &str = "link";

/// The names that the linker knows the objects by. mwldarm's linker script names an object by its file name alone, as
/// in `heap.o(.text)`, and takes the first object of that name in the link, so the objects of two files of one name
/// in different directories, such as `src/heap.c` and `lib/util/heap.c`, can't both be placed. Each such object is
/// linked as a copy named after its file's whole path instead (`src_heap.o`, `lib_util_heap.o`), which the build
/// makes. The name of an object doesn't reach the ROM.
pub struct LinkNames {
    /// The file names, without their extensions, of more than one file
    shared: HashSet<String>,
}

impl LinkNames {
    pub fn new(delinks_map: &DelinksMap) -> Self {
        let mut paths: HashMap<String, HashSet<String>> = HashMap::new();
        for file in delinks_map.delink_files() {
            let (path, _) = file.split_file_ext();
            paths.entry(base_name(&path).to_string()).or_default().insert(path);
        }
        let shared =
            paths.into_iter().filter(|(_, paths)| paths.len() > 1).map(|(name, _)| name).collect();
        Self { shared }
    }

    /// Whether another file has the file name of `file`, so that its object is linked under a name of its path.
    pub fn is_shared(&self, file: &DelinkFile) -> bool {
        let (path, _) = file.split_file_ext();
        self.shared.contains(base_name(&path))
    }

    /// The file name of the object of `file` in the link, by which the linker script names it.
    pub fn object_name(&self, file: &DelinkFile) -> String {
        let (path, _) = file.split_file_ext();
        if self.shared.contains(base_name(&path)) {
            let name = path
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
                .collect::<String>();
            format!("{name}.o")
        } else {
            format!("{}.o", base_name(&path))
        }
    }

    /// The path of the object of `file` in the link's object list: the object to link, or for a shared file name its
    /// copy, under the build path's `link` directory in the file's own directory.
    pub fn link_object(
        &self,
        file: &DelinkFile,
        build_path: &Path,
        delinks_path: &Path,
    ) -> PathBuf {
        if !self.is_shared(file) {
            return object_to_link(file, build_path, delinks_path);
        }
        let (path, _) = file.split_file_ext();
        let dir = Path::new(&path).parent().unwrap_or(Path::new(""));
        build_path.join(LINK_COPIES_DIR).join(dir).join(self.object_name(file)).clean()
    }
}

/// The object that the link takes the code and data of `file` from: its compiled object in `build_path` when the file
/// is complete, else its delinked object in `delinks_path`.
pub fn object_to_link(file: &DelinkFile, build_path: &Path, delinks_path: &Path) -> PathBuf {
    let (path, _) = file.split_file_ext();
    let base_path = if file.complete { build_path } else { delinks_path };
    base_path.join(path).with_extension("o").clean()
}

fn base_name(path: &str) -> &str {
    path.rsplit_once(['/', '\\']).map_or(path, |(_, base)| base)
}
