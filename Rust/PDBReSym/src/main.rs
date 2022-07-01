use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::{prelude::*, stream::iter};
use futures::{stream, Stream, StreamExt};
use ouroboros::self_referencing;
use pdb::{Error, Source};
use rangemap::RangeMap;
use regex::Regex;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use std::collections::btree_map::Range;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::{
    collections::hash_map::Entry,
    env,
    fs::{self, File},
    io,
    io::{prelude::*, BufReader},
    path::{Path, PathBuf},
    vec::Vec,
};
use symbolic_common::{Language, Name, NameMangling};
use symbolic_demangle::{Demangle, DemangleOptions};
use tokio::fs::DirEntry;
use indicatif::{ProgressBar, MultiProgress, ProgressStyle, ProgressDrawTarget};
mod guid;

fn load_txt_file(txt_file: &Path) -> Option<Vec<String>> {
    let file = File::open(txt_file).ok()?;
    let reader = BufReader::new(file);
    Some(
        reader
            .lines()
            .map(|l| l.expect("Could not parse line"))
            .collect(),
    )
}

#[derive(Clone, PartialEq, Eq)]
struct PDBPaths {
    url: String,
    pdb_filename: String,         // filename of pdb
    pdb_cache_dir: PathBuf,       // path to folder containing cached pdb
    pdb_cache_file_path: PathBuf, // full path to cached pdb
}

async fn get_pdb_cache_path_from_binary(binary_path: &Path, cache_dir: &Path) -> Result<PDBPaths> {
    let buffer = tokio::fs::read(binary_path).await?;
    let pe = goblin::pe::PE::parse(&buffer)?;

    let dbg_info = pe
        .debug_data
        .context("failed to fetch debug directory")?
        .codeview_pdb70_debug_info
        .context("pdb debug info is not codeview7 format")?;

    let pdb_guid = guid::GUID::from_le_bytes(dbg_info.signature);
    let pdb_guid_str = pdb_guid.as_hex_str();

    let pdb_age = dbg_info.age;
    let pdb_age_str = format!("{:X}", pdb_age);

    // this filename can contain a null byte at the end, remove it as that's invalid for rust
    let pdb_path = Path::new(std::str::from_utf8(dbg_info.filename)?.trim_matches(char::from(0)));
    let pdb_filename = pdb_path
        .file_name()
        .context("failed to parse pdb to filename")?
        .to_str()
        .context("pdb filename is not valid utf-8")?;

    let pdb_guid_age = pdb_guid_str.to_string() + &pdb_age_str;

    let cache_file_path = cache_dir
        .join(pdb_filename)
        .join(&pdb_guid_age)
        .join(pdb_filename);
    let cache_dir_path = cache_dir.join(pdb_filename).join(&pdb_guid_age);

    return Ok(PDBPaths {
        url: format!(
            "http://msdl.microsoft.com/download/symbols/{}/{}/{}",
            pdb_filename, pdb_guid_age, pdb_filename
        ),
        pdb_filename: pdb_filename.to_string(),
        pdb_cache_dir: cache_dir_path,
        pdb_cache_file_path: cache_file_path,
    });
}

async fn fetch_pdb(binary_path: &Path, cache_dir: &Path, mpb: Arc<MultiProgress>) -> Result<(Bytes, PDBPaths)> {
    let pdb_paths = get_pdb_cache_path_from_binary(binary_path, cache_dir).await?;

    if pdb_paths.pdb_cache_file_path.exists() {
        let data = std::fs::read(&pdb_paths.pdb_cache_file_path)?;
        return Ok((Bytes::from(data), pdb_paths));
    }

    let mut resp = reqwest::Client::builder()
        .build()?
        .get(&pdb_paths.url)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await?;

    let total_size = resp.content_length().expect("Failed to get download size");

    let dl_progressbar = mpb.add(ProgressBar::new(total_size));
    dl_progressbar.set_style(get_pb_dl_style());
    dl_progressbar.set_message(format!("Downloading {}", pdb_paths.pdb_filename));
    dl_progressbar.set_draw_rate(3);
    
    let mut downloaded: u64 = 0;
    tokio::fs::create_dir_all(&pdb_paths.pdb_cache_dir).await.expect("failed to create cache path");

    let mut file = tokio::fs::File::create(&pdb_paths.pdb_cache_file_path).await.expect("failed to create pdb file");

    let mut body = BytesMut::with_capacity(total_size as usize);
    while let Some(chunk) = resp.chunk().await? {
        body.extend(&chunk);
        file.write_all(&chunk).await.expect("Failed to write chunk to pdb file");

        let new = std::cmp::min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        dl_progressbar.set_position(new);
    }

    dl_progressbar.finish_and_clear();

    Ok((body.freeze(), pdb_paths))
}

fn visit_dir(
    path: impl Into<PathBuf>,
) -> impl Stream<Item = io::Result<DirEntry>> + Send + 'static {
    async fn one_level(path: PathBuf, to_visit: &mut Vec<PathBuf>) -> io::Result<Vec<DirEntry>> {
        let mut dir = tokio::fs::read_dir(path).await?;
        let mut files = Vec::new();

        while let Some(child) = dir.next_entry().await? {
            if child.metadata().await?.is_dir() {
                to_visit.push(child.path());
            } else {
                files.push(child)
            }
        }

        Ok(files)
    }

    stream::unfold(vec![path.into()], |mut to_visit| async {
        let path = to_visit.pop()?;
        let file_stream = match one_level(path, &mut to_visit).await {
            Ok(files) => stream::iter(files).map(Ok).left_stream(),
            Err(e) => stream::once(async { Err(e) }).right_stream(),
        };

        Some((file_stream, to_visit))
    })
    .flatten()
}

// recursively iterate windows system dir and cache pdb for each file
async fn build_symbol_cache<'a>(dir: &Path, cache_dir: &Path, mpb: Arc<MultiProgress>) -> Result<()> {
    let mut futures = vec![];
    let mut file_stream = Box::pin(visit_dir(dir));

    // convert file stream into vec of futures
    while let Some(Ok(file)) = file_stream.next().await {
        let file_path = file.path();
        let file_ext = Path::new(&file_path)
            .extension()
            .and_then(std::ffi::OsStr::to_str);
        if let Some(file_ext) = file_ext {
            if file_ext != "exe" && file_ext != "dll" && file_ext != "sys" {
                continue;
            }

            let mpb_clone = mpb.clone();
            let fut = || async move {
                //println!("Downloading {}", file_path.as_os_str().to_str().unwrap());
                let _ = fetch_pdb(&file_path, cache_dir, mpb_clone).await;
            };
            futures.push(fut());
        }
    }

    let cache_progressbar = mpb.add(ProgressBar::new(futures.len() as u64));
    cache_progressbar.set_style(get_pb_style());
    cache_progressbar.set_message("Caching sysdir PDBs");

    let mpb_clone = mpb.clone();
    tokio::task::spawn_blocking(move || {
      let _ = mpb_clone.join(); // polls the drawers
    });

    // wait up to X futures concurrently
    let _results = futures::stream::iter(futures).then(|fut| {
        let cache_progressbar_clone = cache_progressbar.clone();
        async move {
            cache_progressbar_clone.inc(1);
            return fut
        }
    })
    .buffer_unordered(30).collect::<Vec<_>>().await;

    cache_progressbar.finish();

    return Ok(());
}

#[derive(Clone, PartialEq, Eq)]
struct LineSymbol {
    demangled_name: String,
    start_rva: u32,
    end_rva: u32,
}

async fn resolve_symbol_main(
    binary_path: &Path,
    rva: u32,
    symbol_cache_dir: &Path,
    open_pdb_cache: Arc<RwLock<HashMap<PathBuf, RangeMap<u32, LineSymbol>>>>,
    mpb: Arc<MultiProgress>
) -> Result<String> {
    let binary_cache_key = binary_path.to_owned();

    // racy, check if we should try the long task of loading the pdb. Done this way so async task isn't holding the lock
    let should_try_insert;
    {
        let pdb_cache = open_pdb_cache.read().await;
        should_try_insert = !pdb_cache.contains_key(&binary_cache_key);
    }

    // await pdb loading, do this while _NOT_ locking
    if should_try_insert {
        // download the pdb OR load it from the local file cache
        let (pdb_bytes, pdb_paths) = fetch_pdb(binary_path, symbol_cache_dir, mpb.clone()).await?;

        // MS symbol server gives us a 0 bytes pdb sometimes. Ignore that...
        if pdb_bytes.len() == 0 {
            return Err(anyhow!("Zero byte PDB"));
        }

        // build an in memory cache mapping lines to symbols
        let binary_cache_key_clone = binary_cache_key.clone();
        let line_table_cache: Result<_, anyhow::Error> = tokio::task::spawn_blocking(move || {
            let mut pdb =
                pdb::PDB::open(std::io::Cursor::new(pdb_bytes)).context("Failed to open PDB")?;
            let context_data = pdb_addr2line::ContextPdbData::try_from_pdb_ref(&mut pdb)
                .context("Failed to locate PDB info")?;
            let context = context_data
                .make_context()
                .context("Failed to parse PDB info")?;

            let cache_progressbar = mpb.add(ProgressBar::new(context.function_count() as u64));
            cache_progressbar.set_style(get_pb_style());
            cache_progressbar.set_message(format!("Building {} symbol cache...", pdb_paths.pdb_filename));

            let mut line_table = RangeMap::new();
            //println!("Building line cache for {}", pdb_path_str);

            // if a line has no end rva, the start of the next block defines it's end. Lots of symbols are like this.
            // we have to handle it by record the partially resolved line from last loop iteration, then fill in end rva.
            let mut prev_partial_line: Option<LineSymbol> = None;
            for f in context.functions() {
                cache_progressbar.inc(1);

                if let Some(name) = f.name {
                    let mangled_name = Name::new(name, NameMangling::Unknown, Language::Unknown);
                    let demanged_named = mangled_name.try_demangle(DemangleOptions::name_only()).to_string();

                    if let Some(mut partial_line) = prev_partial_line.as_mut() {
                        partial_line.end_rva = f.start_rva;
                        line_table.insert(partial_line.start_rva..partial_line.end_rva, partial_line.clone());
                        //println!("{} {:08X} {:08X} {}", pdb_paths.pdb_filename, partial_line.start_rva, partial_line.end_rva, partial_line.demangled_name);
                        prev_partial_line = None;
                    }

                    if let Some(end_rva) = f.end_rva {
                        let range = f.start_rva..end_rva;
                        let line = LineSymbol {
                            demangled_name: demanged_named,
                            start_rva: f.start_rva,
                            end_rva: end_rva,
                        };
    
                        //println!("{} {:08X} {:08X} {}", pdb_paths.pdb_filename,f.start_rva, end_rva, line.demangled_name);
                        line_table.insert(range, line);
                    } else {
                        prev_partial_line = Some(
                            LineSymbol {
                                demangled_name: demanged_named,
                                start_rva: f.start_rva,
                                end_rva: 0,
                            }
                        );
                    }
                } else {
                    prev_partial_line = None
                }
            }
            cache_progressbar.finish_and_clear();
            Ok(line_table)
        })
        .await?;

        // lock again, may insert, may throw that cache away if another thing raced us.
        let mut pdb_cache = open_pdb_cache.write().await;
        let _ = pdb_cache.insert(binary_cache_key_clone, line_table_cache?);
    }

    // whew, ok lookup the RVA in the range map to find the function name we're nearest [start, end)
    let pdb_cache = open_pdb_cache.read().await;
    let lines = pdb_cache
        .get(&binary_cache_key)
        .context("Failed to load cached PDB")?;
    let line = lines.get(&rva).context("No symbol found for line")?;

    let module_name = binary_path.file_stem().expect("Failed to get filename for modulename").to_str().unwrap();

    // resolve rva to offset from fn start
    let new_line = format!("{}!{} +0x{:04X}", module_name, line.demangled_name, rva - line.start_rva);

    return Ok(new_line);
}

fn get_pb_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("[{elapsed}] {bar:40.green/red} {pos:>7}/{len:7} {eta} {msg}")
        .progress_chars("##-")
}

fn get_pb_dl_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("[{elapsed}] {bar:40.green/red} {bytes}/{total_bytes} ({bytes_per_sec}) {eta} {msg}")
        .progress_chars("##-")
}

#[tokio::main]
async fn main() {
    let matches = clap::App::new("flareup server")
    .author("Stephen Eckels")
    .arg(
        clap::Arg::new("logfile").help("Path to strace log file").required(true)
    )
    .arg(
        clap::Arg::new("outfile").help("Path to write symbolicated output file").required(true)
    )
    .arg(
        clap::Arg::new("cachefolder").help("Path to directory to cache PDBs").long("cachefolder").required(false).default_value("C:\\symbols")
    )
    .arg(
        clap::Arg::new("sysdir").help("Path to folder containing windows system binaries").long("sysdir").required(false).default_value("C:\\Windows\\System32\\")
    )
    .arg(
        clap::Arg::new("cachesyms").help("If provided, iterates the windows system32 directory and caches all PDBs concurrently before symbolication").short('c').long("cachesyms").required(false)
    ).get_matches();

    let symbol_cache_dir = Path::new(matches.value_of("cachefolder").expect("Failed to read cachefolder argument for symbol cache"));
    let system_directory = Path::new(matches.value_of("sysdir").expect("Failed to read sysdir argument for symbol cache source binaries"));
    fs::create_dir_all(&symbol_cache_dir).expect("Failed to create symbol cache directory");

    // binary file path -> range: RVA_start..RVA_end = PDB Function Line Info
    let open_pdbs: HashMap<PathBuf, RangeMap<u32, LineSymbol>> = HashMap::new();

    let open_pdb_arc = Arc::new(RwLock::new(open_pdbs));

    let logfile = Path::new(
        matches
            .value_of("logfile")
            .expect("logfile argument not provided"),
    );

    let outfile = Path::new(
        matches
            .value_of("outfile")
            .expect("outfile argument not provided"),
    );

    let mpb = Arc::new(MultiProgress::with_draw_target(ProgressDrawTarget::stdout()));

    // before anything, download the symbols for everything in the windows directory.
    // this is much faster, as this is able to concurrently download things. The loop below waits per file.
    if matches.contains_id("cachesyms") {
        let _ = build_symbol_cache(system_directory, symbol_cache_dir, mpb.clone()).await;
    }

    if let Some(loglines) = load_txt_file(Path::new(logfile)) {
        let log_progressbar = mpb.add(ProgressBar::new(loglines.len() as u64));
        log_progressbar.set_style(get_pb_style());
        log_progressbar.set_message("Symbolicating");

        let mpb_clone = mpb.clone();
        tokio::task::spawn_blocking(move || {
          let _ = mpb_clone.join(); // polls the drawers
        });

        // 10:49:00.035  INF #1   1136    [C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll] +0x006df961
        // (?<prefix>.*?)\[(?<path>.*?)\]\s+\+(?<offset>0x[0-9a-fA-F]+)
        let regx = Regex::new("(.*?)\\[(.*?)\\]\\s+\\+(0x[0-9a-fA-F]+)(.*)").unwrap();

        let transformed_lines = stream::iter(loglines)
            .then(|line| {
                let open_pdb_clone = open_pdb_arc.clone();
                let regx_clone = regx.clone();
                let log_progressbar_clone = log_progressbar.clone();
                let mpb_clone = mpb.clone();

                // this async block is run 1 by 1 per each element
                async move {
                    log_progressbar_clone.inc(1);
                    if let Some(captures) = regx_clone.captures(&line) {
                        let line_prefix = captures.get(1).map_or("", |m| m.as_str());
                        let path = captures
                            .get(2)
                            .map_or("", |m| m.as_str())
                            .replace("\\SystemRoot\\", "C:\\Windows\\");
                        let offset_str = captures.get(3).map_or("", |m| m.as_str());
                        let line_suffix = captures.get(4).map_or("", |m| m.as_str());

                        let offset = u64::from_str_radix(offset_str.trim_start_matches("0x"), 16)
                            .unwrap() as u32;

                        if let Ok(symbol) = resolve_symbol_main(
                            Path::new(&path),
                            offset,
                            symbol_cache_dir,
                            open_pdb_clone.clone(),
                            mpb_clone
                        )
                        .await
                        {
                            return format!("{}{}{}", line_prefix, symbol, line_suffix);
                        }
                    }
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .await;

        let out_progressbar = mpb.add(ProgressBar::new(transformed_lines.len() as u64));
        out_progressbar.set_style(get_pb_style());
        out_progressbar.set_message("Writing Output");

        let mut h_outfile = tokio::fs::File::create(outfile).await.expect("Failed to create output file");
        for line in transformed_lines {
            out_progressbar.inc(1);
            let _ = h_outfile.write((line + "\n").as_bytes()).await.expect("Failed to write to output file");
        }

        log_progressbar.finish();
        out_progressbar.finish();
    }
}
