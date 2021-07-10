//! Supports running the system-provided OpenSSH binaries to test compatibility.

use tokio::process::{self, Command};

/// A launched OpenSSH daemon instance.
pub struct Sshd {
    /// The child process that runs sshd.
    pub process: process::Child,
    /// The relevant output stream from the sshd process.
    pub output_stream: process::ChildStderr,
    /// The output of the sshd process that was read so far.
    pub output: Vec<u8>,
    /// The port that sshd is listening on.
    pub port: u16,
    /// The current working directory of the sshd process, where the host key file lives.
    pub temp_dir: mktemp::Temp,
}

impl Sshd {
    /// Creates a new sshd process.
    pub async fn launch() -> Sshd {
        use std::process::Stdio;

        // Find out the absolute path of sshd, because it only runs with the absolute path
        let sshd_path = quale::which("sshd").expect("could not find sshd binary in the PATH");

        // Set up a temporary folder to hold the ssh key
        let temp_dir = mktemp::Temp::new_dir()
            .ok()
            .expect("could not create a temporary directory");
        let host_key_path = temp_dir.as_path().join("ssh_host_ed25519_key");

        // Generate a new random ssh key
        Command::new("ssh-keygen")
            .arg("-f")
            .arg(&host_key_path)
            .arg("-t")
            .arg("ed25519")
            .current_dir(&temp_dir)
            .stdin(Stdio::null())
            .output()
            .await
            .expect("failed to create ssh key");

        let port = portpicker::pick_unused_port().expect("no free port found");

        let mut process = Command::new(sshd_path)
            .arg("-p")
            .arg(format!("{}", port))
            .arg("-h")
            .arg(&host_key_path)
            .arg("-o")
            .arg("AuthorizedKeysFile /dev/null")
            .arg("-d")
            .current_dir(&temp_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("could not spawn sshd process");

        let output_stream = process
            .stderr
            .take()
            .expect("stderr is present after process creation");

        let mut result = Sshd {
            process,
            output_stream,
            output: Vec::new(),
            port,
            temp_dir,
        };

        // wait until the server is listening
        loop {
            if result
                .read_until_timeout(std::time::Duration::from_millis(100))
                .await
                .map(|output| output.contains("listening on 0.0.0.0"))
                .unwrap_or(false)
            {
                break;
            };
        }

        result
    }

    /// Reads from the child process until a timeout occurs without any new data.
    pub async fn read_until_timeout(&mut self, timeout: std::time::Duration) -> Option<&str> {
        let mut buf = [0; 512];

        use tokio::io::AsyncReadExt as _;
        while let Ok(Ok(len)) =
            tokio::time::timeout(timeout, self.output_stream.read(&mut buf)).await
        {
            self.output.extend(&buf[..len]);
        }

        std::str::from_utf8(&self.output).ok()
    }

    /// Runs the sshd process to completion, returning its output.
    pub async fn run_to_completion(mut self) -> Option<String> {
        self.read_until_timeout(std::time::Duration::from_millis(100))
            .await;

        // kill the process if it's still running
        self.process.kill().ok();

        String::from_utf8(std::mem::replace(&mut self.output, Vec::new())).ok()
    }
}

pub struct Ssh {
    /// The child process that runs sshd.
    pub process: process::Child,
    /// The relevant output stream from the sshd process.
    pub output_stream: process::ChildStderr,
    /// The output of the sshd process that was read so far.
    pub output: Vec<u8>,
}

impl Ssh {
    /// Creates a new ssh process.
    pub async fn launch(port: u16) -> Ssh {
        use std::process::Stdio;

        let mut process = Command::new("ssh")
            .arg("user@localhost")
            .arg("-p")
            .arg(format!("{}", port))
            .arg("-F")
            .arg("none")
            .arg("-o")
            .arg("UserKnownHostsFile none")
            .arg("-o")
            .arg("GlobalKnownHostsFile none")
            .arg("-o")
            .arg("IdentityFile none")
            .arg("-o")
            .arg("NoHostAuthenticationForLocalhost true")
            .arg("-v")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("could not spawn ssh process");

        let output_stream = process
            .stderr
            .take()
            .expect("stderr is present after process creation");

        let mut result = Ssh {
            process,
            output_stream,
            output: Vec::new(),
        };

        // wait until the client is connected
        loop {
            if result
                .read_until_timeout(std::time::Duration::from_millis(100))
                .await
                .map(|output| output.contains("Connection established"))
                .unwrap_or(false)
            {
                break;
            };
        }

        result
    }

    /// Reads from the child process until a timeout occurs without any new data.
    pub async fn read_until_timeout(&mut self, timeout: std::time::Duration) -> Option<&str> {
        let mut buf = [0; 512];

        use tokio::io::AsyncReadExt as _;
        while let Ok(Ok(len)) =
            tokio::time::timeout(timeout, self.output_stream.read(&mut buf)).await
        {
            self.output.extend(&buf[..len]);
        }

        std::str::from_utf8(&self.output).ok()
    }

    /// Runs the sshd process to completion, returning its output.
    pub async fn run_to_completion(mut self) -> Option<String> {
        self.read_until_timeout(std::time::Duration::from_millis(100))
            .await;

        // kill the process if it's still running
        self.process.kill().ok();

        String::from_utf8(std::mem::replace(&mut self.output, Vec::new())).ok()
    }
}
