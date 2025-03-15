use anyhow::Context;
use clap::Parser;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyEntry, Request,
};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid as NixPid;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::thread;
use std::thread::sleep;
use std::thread::JoinHandle;
use std::{
    ffi::OsStr,
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    process::Command,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use sysinfo::System;

const ENOENT: i32 = 2;
const TTL: Duration = Duration::from_secs(1);

#[derive(Parser, Debug, Clone)]
#[command(
    author = "FlorianNAdam",
    about = "Ephemerally overlay file contents at runtime using FUSE"
)]
struct Args {
    #[arg(help = "Path to the file to overlay")]
    file_paths: Vec<String>,

    #[arg(long, help = "Path to file containing list of file_paths")]
    watch_file: Option<PathBuf>,

    #[arg(long, conflicts_with_all = &["exec", "replace_regex", "replace_exec"], help = "Use the specified string as the file content.")]
    content: Option<String>,

    #[arg(long, conflicts_with_all = &["content", "replace_regex", "replace_exec"], help = "Execute a command with the original content; use its output as the file content.")]
    exec: Option<String>,

    #[arg(long, action = clap::ArgAction::Append, conflicts_with_all = &["content", "exec", "replace_exec"], help = "Replace PATTERN with REPLACEMENT in the original content. Format: PATTERN=REPLACEMENT. Can be specified multiple times.")]
    replace_regex: Vec<String>,

    #[arg(long, action = clap::ArgAction::Append, conflicts_with_all = &["content", "exec", "replace_regex"], help = "Replace PATTERN by executing COMMAND. Format: PATTERN=COMMAND. Can be specified multiple times.")]
    replace_exec: Vec<String>,

    #[arg(long, help = "Allow other users to access the mounted filesystem.")]
    allow_other: bool,

    #[arg(
        long,
        default_value = "sh",
        help = "Specify the shell to use for executing commands (default: sh)."
    )]
    shell: String,
}

enum ContentMode {
    Static(String),
    Exec(String),
    ReplaceRegex(Vec<(String, String)>),
    ReplaceExec(Vec<(String, String)>),
    Original,
}

struct MirageFS {
    file_path: String,
    original_content: String,
    mode: ContentMode,
    original_attr: FileAttr,
    shell: String,
}

impl MirageFS {
    fn get_content(&self, req: &Request) -> String {
        match &self.mode {
            ContentMode::Static(data) => data.clone(),
            ContentMode::Exec(command) => self.run_command(command, req),
            ContentMode::ReplaceRegex(pairs) => {
                let mut content = self.original_content.to_string();
                for (target, replacement) in pairs {
                    content = content.replace(target, replacement);
                }
                content
            }
            ContentMode::ReplaceExec(pairs) => {
                let mut content = self.original_content.to_string();
                for (target, command) in pairs {
                    if content.contains(target) {
                        let replacement = self.run_command(command, req);
                        content = content.replace(target, &replacement);
                    }
                }
                content
            }
            ContentMode::Original => self.original_content.to_string(),
        }
    }

    fn run_command(&self, command: &str, req: &Request) -> String {
        match Command::new(&self.shell)
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .uid(req.uid())
            .gid(req.gid())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(stdin) = child.stdin.as_mut() {
                    if stdin.write_all(self.original_content.as_bytes()).is_err() {
                        eprintln!("Failed to write to command stdin");
                        return String::new();
                    }
                }
                match child.wait_with_output() {
                    Ok(output) => {
                        if output.status.success() {
                            String::from_utf8_lossy(&output.stdout).to_string()
                        } else {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            eprintln!(
                                "Failed to run command for file {} with stderr:",
                                self.file_path
                            );
                            eprintln!("{}", stderr);
                            String::new()
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to read command output: {}", e);
                        String::new()
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to execute command '{}': {}", command, e);
                String::new()
            }
        }
    }

    fn get_attr(&self, req: &Request) -> FileAttr {
        let dynamic_size = self.get_content(req).len() as u64;
        let mut updated_attr = self.original_attr;
        updated_attr.size = dynamic_size;
        updated_attr
    }
}

impl Filesystem for MirageFS {
    fn lookup(&mut self, req: &Request, parent: u64, _name: &OsStr, reply: ReplyEntry) {
        if parent == 1 {
            reply.entry(&TTL, &self.get_attr(req), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == 1 {
            reply.attr(&TTL, &self.get_attr(req));
        } else {
            reply.error(ENOENT);
        }
    }

    fn read(
        &mut self,
        req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == 1 {
            let content = self.get_content(req);
            let data = &content.as_bytes()
                [offset as usize..(offset as usize + size as usize).min(content.len())];
            reply.data(data);
        } else {
            reply.error(ENOENT);
        }
    }
}

fn parse_pairs(pairs: Vec<String>) -> Vec<(String, String)> {
    pairs
        .into_iter()
        .filter_map(|pair| match pair.split_once('=') {
            Some((k, v)) => Some((k.to_string(), v.to_string())),
            None => {
                eprintln!("Invalid format, expected PATTERN=REPLACEMENT or PATTERN=COMMAND");
                None
            }
        })
        .collect()
}

fn add_mirage_fs(file_path: String, args: &Args) -> anyhow::Result<MirageHandle> {
    let args = args.clone();

    println!("adding mirage to file: {:?}", file_path);

    let original_content = fs::read_to_string(&file_path)
        .context("Failed to read file")
        .with_context(|| format!("Failed to add mirage fs to file: {:?}", file_path))?;

    let mode = if let Some(content) = args.content {
        ContentMode::Static(content)
    } else if let Some(exec) = args.exec {
        ContentMode::Exec(exec)
    } else if !args.replace_regex.is_empty() {
        ContentMode::ReplaceRegex(parse_pairs(args.replace_regex))
    } else if !args.replace_exec.is_empty() {
        ContentMode::ReplaceExec(parse_pairs(args.replace_exec))
    } else {
        ContentMode::Original
    };

    let original_metadata = fs::metadata(&file_path)
        .context("Failed to read file metadata")
        .with_context(|| format!("Failed to add mirage fs to file: {:?}", file_path))?;

    let original_attr = FileAttr {
        ino: 1,
        size: original_content.len() as u64,
        blocks: 1,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: original_metadata.permissions().mode() as u16,
        nlink: original_metadata.nlink() as u32,
        uid: original_metadata.uid(),
        gid: original_metadata.gid(),
        rdev: 0,
        flags: 0,
        blksize: 512,
    };

    let mut options = vec![
        MountOption::RO,
        MountOption::FSName("miragefs".to_string()),
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
    ];

    if args.allow_other {
        options.push(MountOption::AllowOther);
    }

    let filesystem = MirageFS {
        file_path: file_path.clone(),
        original_content,
        mode,
        original_attr,
        shell: args.shell,
    };

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let handle = thread::spawn(move || {
        let fusers_handle = fuser::spawn_mount2(filesystem, file_path, &options)
            .expect("Failed to mount filesystem");

        shutdown_rx.recv().expect("Failed to receive from channel");

        fusers_handle.join();
    });

    Ok(MirageHandle {
        thread: handle,
        shutdown_tx,
    })
}

struct MirageHandle {
    thread: JoinHandle<()>,
    shutdown_tx: Sender<()>,
}

impl MirageHandle {
    fn shutdown(self) {
        self.shutdown_tx
            .send(())
            .expect("Failed to send shutdown to thread");

        self.thread.join().expect("Fuser mount thread panicked");
    }
}

fn terminate_children() {
    send_to_children(Signal::SIGTERM);

    sleep(Duration::from_secs(1));

    send_to_children(Signal::SIGKILL);
}

fn send_to_children(signal: Signal) {
    let mut system = System::new_all();
    system.refresh_all();

    let current_pid = sysinfo::Pid::from_u32(std::process::id() as u32);

    for (&pid, process) in system.processes() {
        if process.parent() == Some(current_pid) {
            if process.name() == "fusermount3" {
                if let Err(e) = kill(NixPid::from_raw(pid.as_u32() as i32), signal) {
                    eprintln!("Failed to kill process {}: {}", pid, e);
                }
            }
        }
    }
}

fn watch_file_thread(
    file_path: PathBuf,
    args: Args,
    handles: Arc<Mutex<Vec<MirageHandle>>>,
) -> notify::Result<()> {
    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&file_path, RecursiveMode::NonRecursive)?;

    let mut watched_files = HashSet::new();

    process_watch_file(
        file_path.clone(),
        &args,
        &mut watched_files,
        handles.clone(),
    );
    for event in rx {
        match event {
            Ok(event) if matches!(event.kind, EventKind::Modify(_)) => {
                process_watch_file(
                    file_path.clone(),
                    &args,
                    &mut watched_files,
                    handles.clone(),
                );
            }
            Err(e) => eprintln!("Watch error: {:?}", e),
            _ => {}
        }
    }

    Ok(())
}

fn process_watch_file(
    file_path: PathBuf,
    args: &Args,
    watched_files: &mut HashSet<String>,
    handles: Arc<Mutex<Vec<MirageHandle>>>,
) {
    if let Ok(file) = OpenOptions::new().read(true).open(&file_path) {
        let reader = BufReader::new(file);
        for file in reader.lines().flatten() {
            if watched_files.insert(file.clone()) {
                match add_mirage_fs(file.clone(), &args) {
                    Ok(handle) => {
                        let mut handles = handles
                            .lock()
                            .expect("Failed to obtain lock for mirage handles");
                        handles.push(handle);
                    }
                    Err(e) => {
                        eprintln!("{:?}", e);
                    }
                }
            }
        }
    }
}

fn signal_handler(handles: Arc<Mutex<Vec<MirageHandle>>>) {
    // wait for signal
    let mut signals = Signals::new(&[SIGTERM, SIGINT]).unwrap();
    for sig in signals.forever() {
        match sig {
            SIGINT | SIGTERM => {}
            _ => continue,
        }

        println!("Received shutdown signal");

        let mut handles = handles
            .lock()
            .expect("Failed to obtain lock for mirage handles");

        let handles = std::mem::take(&mut *handles);

        for handle in handles {
            handle.shutdown();
        }

        break;
    }

    // clean-up just to be safe
    terminate_children();
}

fn main() {
    let args = Args::parse();

    let paths = args.clone().file_paths.into_iter();

    // create fusers mount thread for each file
    let mut handles = Vec::new();
    for file_path in paths {
        match add_mirage_fs(file_path.clone(), &args) {
            Ok(handle) => {
                handles.push(handle);
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }

    let handles = Arc::new(Mutex::new(handles));

    // spawn watcher thread
    if let Some(watch_file) = args.watch_file.clone() {
        let watch_file_thread = thread::spawn({
            let args = args.clone();
            let handles = handles.clone();
            move || watch_file_thread(watch_file, args, handles)
        });

        watch_file_thread.join().unwrap().unwrap();
    }

    signal_handler(handles);
}
