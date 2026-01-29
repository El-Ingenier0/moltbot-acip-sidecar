use std::{
    process::{Child, Command},
    time::{Duration, Instant},
};

pub fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_moltbot-acip-sidecar")
}

/// A small helper to spawn the binary in tests and ensure we never hang.
pub struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    pub fn spawn(mut cmd: Command) -> std::io::Result<Self> {
        let child = cmd.spawn()?;
        Ok(Self { child })
    }

    pub fn wait_for(&mut self, max: Duration) {
        let deadline = Instant::now() + max;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => return,
            }
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        // Best-effort cleanup to prevent runaway servers in test runs.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn cmd() -> Command {
    Command::new(bin_path())
}
