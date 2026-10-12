use crate::model::{Failure, Result};
use std::collections::BTreeMap;

pub(crate) fn validate(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > 1024 || !path.is_ascii() {
        return Err(
            Failure::invalid("path.invalid", "Paths must be ASCII and at most 1024 bytes").at(path),
        );
    }
    for part in path.split('/') {
        let valid_edge = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
        let bytes = part.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 255
            || !valid_edge(bytes[0])
            || !valid_edge(bytes[bytes.len() - 1])
            || !bytes.iter().all(|b| valid_edge(*b) || *b == b'.')
        {
            return Err(
                Failure::invalid("path.invalid", "Invalid technical path component").at(path),
            );
        }
        let base = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let device = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && matches!(base.as_bytes()[3], b'1'..=b'9'));
        if device {
            return Err(
                Failure::invalid("path.device_name", "Windows device names are forbidden").at(path),
            );
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Node {
    pub path: String,
    pub directory: bool,
    explicit: bool,
}

pub(crate) type Nodes = BTreeMap<String, Node>;

pub(crate) fn insert(nodes: &mut Nodes, path: &str, directory: bool) -> Result<()> {
    validate(path)?;
    let mut parents = Vec::new();
    let mut prefix = path;
    while let Some((parent, _)) = prefix.rsplit_once('/') {
        parents.push(parent);
        prefix = parent;
    }
    for parent in parents.into_iter().rev() {
        insert_node(nodes, parent, true, false)?;
    }
    insert_node(nodes, path, directory, true)
}

fn insert_node(nodes: &mut Nodes, path: &str, directory: bool, explicit: bool) -> Result<()> {
    let key = path.to_ascii_lowercase();
    if let Some(node) = nodes.get_mut(&key) {
        if node.path != path || node.directory != directory || (explicit && node.explicit) {
            return Err(Failure::invalid(
                "path.collision",
                "Duplicate, case-folded or file/directory path collision",
            )
            .at(path));
        }
        node.explicit |= explicit;
    } else {
        nodes.insert(
            key,
            Node {
                path: path.into(),
                directory,
                explicit,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_and_ambiguous_paths() {
        for path in [
            "../x", "/x", "x\\y", "con.txt", "a/COM9", "x.", "a//b", "a b", "a%20b", "é",
        ] {
            assert!(validate(path).is_err(), "{path}");
        }
        let mut nodes = Nodes::new();
        insert(&mut nodes, "Data/a", false).unwrap();
        assert!(insert(&mut nodes, "data/b", false).is_err());
        assert!(insert(&mut nodes, "Data", false).is_err());
        insert(&mut nodes, "Data", true).unwrap();
        assert!(insert(&mut nodes, "Data", true).is_err());
    }
}
