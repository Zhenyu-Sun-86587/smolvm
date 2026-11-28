//! Provision immutable remote members through a protected Worker-local broker.

use crate::{
    blocks::{self, BlockObject},
    catalog::Catalog,
    ipc::{self, valid_digest, valid_id, Fault, Request, Result},
    managed::DiskSet,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io,
    os::{
        fd::OwnedFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Base {
    resource_id: String,
    closure_digest: String,
    manifest_digest: String,
    member_digest: String,
    member_bytes: u64,
    broker_socket: PathBuf,
}

fn unavailable(message: impl ToString) -> Fault {
    Fault::new("E_BUCKET_BASE_UNAVAILABLE", message.to_string())
}

fn acceptable_owner(uid: u32, admin: u32) -> bool {
    uid == 0 || uid == admin
}

fn inspect_socket(path: &Path, admin: u32) -> io::Result<()> {
    if !path.is_absolute() || path.as_os_str().len() >= 108 || path.canonicalize()? != path {
        return Err(io::Error::other(
            "Bucket broker socket must be a canonical local path",
        ));
    }
    let socket = fs::symlink_metadata(path)?;
    if !socket.file_type().is_socket()
        || !acceptable_owner(socket.uid(), admin)
        || socket.mode() & 0o022 != 0
    {
        return Err(io::Error::other(
            "Bucket broker socket needs a trusted owner and private permissions",
        ));
    }
    let mut parent = path.parent();
    while let Some(dir) = parent {
        let meta = fs::symlink_metadata(dir)?;
        if !meta.is_dir() || !acceptable_owner(meta.uid(), admin) || meta.mode() & 0o022 != 0 {
            return Err(io::Error::other(
                "Bucket broker socket requires a protected parent path",
            ));
        }
        parent = dir.parent();
    }
    Ok(())
}

pub(crate) fn connect(path: &Path, admin: u32) -> Result<OwnedFd> {
    inspect_socket(path, admin).map_err(unavailable)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(unavailable)?;
    let address = SockAddr::unix(path).map_err(unavailable)?;
    socket
        .connect_timeout(&address, Duration::from_secs(2))
        .map_err(unavailable)?;
    if !acceptable_owner(ipc::peer(&socket).map_err(unavailable)?.uid, admin) {
        return Err(unavailable("Bucket broker peer credentials changed"));
    }
    Ok(socket.into())
}

pub(crate) fn register(
    catalog: &Catalog,
    objects: &File,
    request: &Request,
    admin: u32,
) -> Result<Value> {
    let base: Base = request.payload()?;
    let bundle = request
        .bundle_digest
        .as_deref()
        .filter(|bundle| valid_digest(bundle) && request.route_id.as_deref() == Some("deep"))
        .ok_or_else(|| Fault::invalid("Bucket base requires a registered deep Worker route"))?;
    if !valid_id(&base.resource_id)
        || !valid_digest(&base.closure_digest)
        || !valid_digest(&base.manifest_digest)
        || !valid_digest(&base.member_digest)
        || base.member_bytes == 0
        || base.member_bytes > i64::MAX as u64
    {
        return Err(Fault::invalid("invalid Bucket immutable base"));
    }
    catalog.bundle(bundle)?;
    let expected: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_blocks b JOIN operations o USING(operation_id)
          WHERE b.resource_id=? AND o.route_id='deep' AND o.bundle_digest=?)",
        params![base.resource_id, bundle],
        |row| row.get(0),
    )?;
    if !expected {
        return Err(Fault::new(
            "E_NOT_FOUND",
            "Bucket base is outside this registered bundle",
        ));
    }
    let object = catalog
        .block_closure(&base.resource_id)?
        .into_iter()
        .next()
        .ok_or_else(|| unavailable("Bucket generation has no local identity"))?;
    if object.spec.mutable() || physical_len(objects, &object)? != base.member_bytes {
        return Err(Fault::invalid(
            "Bucket base requires the exact immutable member and physical size",
        ));
    }
    let mut contents = blocks::open_object(objects, &object, false)?;
    let mut hash = Sha256::new();
    if io::copy(&mut contents, &mut hash).map_err(unavailable)? != base.member_bytes
        || format!("sha256:{:x}", hash.finalize()) != base.member_digest
    {
        return Err(Fault::invalid(
            "Bucket member digest differs from the exact immutable generation",
        ));
    }
    drop(connect(&base.broker_socket, admin)?);
    let broker = base
        .broker_socket
        .to_str()
        .ok_or_else(|| Fault::invalid("Bucket broker socket requires UTF-8"))?;
    catalog.db.execute(
        "INSERT INTO bucket_block_bases VALUES(?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
        params![
            base.resource_id,
            bundle,
            base.closure_digest,
            base.manifest_digest,
            base.member_digest,
            base.member_bytes as i64,
            broker
        ],
    )?;
    let same: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM bucket_block_bases WHERE resource_id=? AND bundle_digest=?
         AND closure_digest=? AND manifest_digest=? AND member_digest=? AND member_bytes=? AND broker_socket=?)",
        params![
            base.resource_id,
            bundle,
            base.closure_digest,
            base.manifest_digest,
            base.member_digest,
            base.member_bytes as i64,
            broker
        ],
        |row| row.get(0),
    )?;
    if !same {
        return Err(Fault::new(
            "E_IDEMPOTENCY_CONFLICT",
            "Bucket generation already has a different immutable locator",
        ));
    }
    Ok(
        json!({"resource_id":base.resource_id,"closure_digest":base.closure_digest,
        "manifest_digest":base.manifest_digest,"member_digest":base.member_digest,"member_bytes":base.member_bytes}),
    )
}

fn physical_len(objects: &File, object: &BlockObject) -> Result<u64> {
    blocks::open_object(objects, object, false)?
        .metadata()
        .map(|metadata| metadata.len())
        .map_err(unavailable)
}

pub(crate) fn launch(
    catalog: &Catalog,
    objects: &File,
    bundle: &str,
    layouts: &[DiskSet],
    admin: u32,
) -> Result<BTreeMap<String, (u64, OwnedFd)>> {
    let mut sockets = BTreeMap::new();
    let mut visited = HashSet::new();
    for layer in layouts.iter().flat_map(|set| &set.layers) {
        let id = &layer.spec.resource_id;
        if !visited.insert(id) || layer.spec.mutable() {
            continue;
        }
        let stored: Option<(i64, String)> = catalog.db.query_row(
            "SELECT member_bytes,broker_socket FROM bucket_block_bases WHERE resource_id=? AND bundle_digest=?",
            params![id,bundle], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional()?;
        if let Some((bytes, broker)) = stored {
            let bytes = u64::try_from(bytes).map_err(unavailable)?;
            if physical_len(objects, layer)? != bytes {
                return Err(unavailable(
                    "declared remote member differs from its sealed layer identity",
                ));
            }
            sockets.insert(id.clone(), (bytes, connect(Path::new(&broker), admin)?));
        }
    }
    Ok(sockets)
}
