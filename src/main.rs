use clap::Parser;
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyEntry, Request,
};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid as NixPid;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
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
    original_content: Arc<String>,
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
                    content = content.replace(target, &self.run_command(command, req));
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
                    Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
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

fn fuser_mount_thread(file_path: String, args: Args, shutdown_rx: Receiver<()>) {
    let original_content = match fs::read_to_string(&file_path) {
        Ok(content) => Arc::new(content),
        Err(e) => {
            eprintln!("Failed to read file '{}': {}", file_path, e);
            return;
        }
    };

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

    let original_metadata = match fs::metadata(&file_path) {
        Ok(metadata) => metadata,
        Err(e) => {
            eprintln!("Failed to read file metadata: {}", e);
            return;
        }
    };

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
        original_content,
        mode,
        original_attr,
        shell: args.shell,
    };

    let fusers_handle =
        fuser::spawn_mount2(filesystem, &file_path, &options).expect("Failed to mount filesystem");

    shutdown_rx.recv().expect("Failed to receive from channel");

    println!("Received shutdown");
    fusers_handle.join();
    println!("Unmounted and joined fusers");
}

fn signal_handler_thread(handles: Vec<FusersHandle>) {
    let mut signals = Signals::new(&[SIGTERM, SIGINT]).unwrap();
    for sig in signals.forever() {
        match sig {
            SIGINT => {
                println!("Received SIGINT (Ctrl+C)");
            }
            SIGTERM => {
                println!("Received SIGTERM");
            }
            _ => continue,
        }

        println!("Sending to shutdown_txs");
        for handle in handles {
            println!("Sending to shutdown_tx");

            handle
                .shutdown_tx
                .send(())
                .expect("Failed to send shutdown to thread");

            handle.thread.join().expect("Fuser mount thread panicked");
        }

        println!("All sent!");

        break;
    }
}

struct FusersHandle {
    thread: JoinHandle<()>,
    shutdown_tx: Sender<()>,
}

fn terminate_children() {
    println!("Terminating remaining children");

    let mut system = System::new_all();
    system.refresh_all();

    let current_pid = sysinfo::Pid::from_u32(std::process::id() as u32);

    for (&pid, process) in system.processes() {
        let parent = process.parent();

        if process.parent() == Some(current_pid) {
            if process.name() == "fusermount3" {
                println!("Found direct child: {:?} ({})", process.name(), pid);

                if let Err(e) = kill(NixPid::from_raw(pid.as_u32() as i32), Signal::SIGTERM) {
                    eprintln!("Failed to kill process {}: {}", pid, e);
                }
            }
        }
    }
}

fn main() {
    let args = Args::parse();

    let paths = args.clone().file_paths.into_iter();

    // create fusers mount thread for each file
    let handles = paths
        .into_iter()
        .map(|file_path| {
            let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

            let handle = thread::spawn({
                let args = args.clone();
                move || fuser_mount_thread(file_path, args, shutdown_rx)
            });

            FusersHandle {
                thread: handle,
                shutdown_tx,
            }
        })
        .collect::<Vec<_>>();

    println!("Created {} threads", handles.len());

    // Create signal handler thread
    let signal_handle = thread::spawn(move || signal_handler_thread(handles));

    // wait for signal handler thread to terminate
    signal_handle.join().expect("Signal handler panicked");

    println!("Signal handler thread terminated");

    terminate_children();
}
