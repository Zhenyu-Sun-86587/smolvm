//! A fresh, Worker-owned channel to one measured restored VMM.

use crate::ipc::{self, Fault, Result};
use socket2::{Domain, Socket, Type};
use std::cell::Cell;
use std::os::fd::OwnedFd;

pub(crate) const FRAME_SIZE: usize = 192;
pub(crate) const NETWORK_FRAME_SIZE: usize = 256;
const NETWORK_START_HEADER: &[u8; 8] = b"SGI2\x02\0\0\0";
const START_HEADER: &[u8; 8] = b"SGI1\x01\0\0\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityPhase {
    Applying,
    IdentityReady,
    Activating,
    Released,
    FailedHeld,
}

pub(crate) struct TargetAuthority {
    worker: Socket,
    vmm: Option<Socket>,
    pending_reply: Cell<bool>,
    binding: [u8; 56],
}

impl TargetAuthority {
    pub(crate) fn new(challenge: [u8; 16], epoch: u64, context: [u8; 32]) -> Result<Self> {
        if challenge == [0; 16] || epoch == 0 || context == [0; 32] {
            return Err(Fault::invalid(
                "target authority needs a challenge, context and epoch",
            ));
        }
        let (worker, vmm) = Socket::pair(Domain::UNIX, Type::SEQPACKET, None).map_err(transport)?;
        ipc::set_timeout(&worker).map_err(transport)?;
        let mut binding = [0; 56];
        binding[..16].copy_from_slice(&challenge);
        binding[16..24].copy_from_slice(&epoch.to_le_bytes());
        binding[24..].copy_from_slice(&context);
        Ok(Self {
            worker,
            vmm: Some(vmm),
            pending_reply: Cell::new(false),
            binding,
        })
    }

    pub(crate) fn duplicate_for_vmm(&self) -> Result<OwnedFd> {
        self.vmm
            .as_ref()
            .ok_or_else(|| Fault::new("E_STALE_REVISION", "authority offer ended"))?
            .try_clone()
            .map(Into::into)
            .map_err(transport)
    }

    pub(crate) fn check_frame(&self, frame: &[u8]) -> Result<()> {
        let header = match frame.len() {
            FRAME_SIZE => START_HEADER,
            NETWORK_FRAME_SIZE => NETWORK_START_HEADER,
            _ => return Err(Fault::invalid("invalid identity frame size")),
        };
        if &frame[..8] != header || frame[8..64] != self.binding {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "identity frame does not match this authority",
            ));
        }
        Ok(())
    }

    pub(crate) fn begin(&mut self, frame: &[u8]) -> Result<IdentityPhase> {
        self.check_frame(frame)?;
        self.vmm = None;
        let mut packet = [0; NETWORK_FRAME_SIZE + 1];
        packet[0] = 1;
        let length = frame.len() + 1;
        packet[1..length].copy_from_slice(frame);
        self.exchange(&packet[..length])
    }

    pub(crate) fn status(&self) -> Result<IdentityPhase> {
        self.scoped_exchange(2)
    }

    pub(crate) fn release(&self) -> Result<IdentityPhase> {
        self.scoped_exchange(3)
    }

    fn scoped_exchange(&self, command: u8) -> Result<IdentityPhase> {
        let mut packet = [0; 57];
        packet[0] = command;
        packet[1..].copy_from_slice(&self.binding);
        self.exchange(&packet)
    }

    fn exchange(&self, packet: &[u8]) -> Result<IdentityPhase> {
        // A delayed response belongs to the previous command. Drain it before
        // sending a new command because the VMM response has no request ID.
        if self.pending_reply.get() {
            self.receive_reply()?;
        }
        ipc::send(&self.worker, packet).map_err(transport)?;
        self.pending_reply.set(true);
        self.receive_reply()
    }

    fn receive_reply(&self) -> Result<IdentityPhase> {
        let response = ipc::receive(&self.worker).map_err(|error| {
            if error.code == "E_TRANSPORT" {
                Fault::new("E_FENCE_UNPROVEN", "cannot observe the target authority")
            } else {
                error
            }
        })?;
        self.pending_reply.set(false);
        match response.as_slice() {
            b"OK applying" => Ok(IdentityPhase::Applying),
            b"OK identity_ready" => Ok(IdentityPhase::IdentityReady),
            b"OK activating" => Ok(IdentityPhase::Activating),
            b"OK released" => Ok(IdentityPhase::Released),
            b"OK failed_held" => Ok(IdentityPhase::FailedHeld),
            reply if reply.starts_with(b"ERR ") => Err(Fault::new(
                "E_IDENTITY_REJECTED",
                "the target rejected the scoped identity command",
            )),
            _ => Err(Fault::new(
                "E_PROTOCOL_UNSUPPORTED",
                "unknown target authority reply",
            )),
        }
    }
}

fn transport(error: std::io::Error) -> Fault {
    eprintln!("target authority transport: {error}");
    Fault::new(
        "E_FENCE_UNPROVEN",
        "cannot establish target authority transport",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn worker_owns_the_authority_and_uses_the_exact_scope_for_each_command() {
        let mut authority = TargetAuthority::new([1; 16], 7, [2; 32]).unwrap();
        let vmm = Socket::from(authority.duplicate_for_vmm().unwrap());
        let mut frame = [3; FRAME_SIZE];
        frame[..8].copy_from_slice(START_HEADER);
        frame[8..64].copy_from_slice(&authority.binding);
        let mut old = frame;
        old[24] = 6;
        assert_eq!(authority.begin(&old).unwrap_err().code, "E_STALE_EXECUTION");
        let peer = thread::spawn(move || {
            for (command, answer) in [
                (1, b"OK applying".as_slice()),
                (2, b"OK identity_ready".as_slice()),
                (3, b"OK released".as_slice()),
            ] {
                let request = ipc::receive(&vmm).unwrap();
                assert_eq!(request[0], command);
                if command == 1 {
                    assert_eq!(&request[1..], &frame);
                } else {
                    assert_eq!(&request[1..], &frame[8..64]);
                }
                ipc::send(&vmm, answer).unwrap();
            }
        });
        assert_eq!(authority.begin(&frame).unwrap(), IdentityPhase::Applying);
        assert_eq!(authority.status().unwrap(), IdentityPhase::IdentityReady);
        assert_eq!(authority.release().unwrap(), IdentityPhase::Released);
        peer.join().unwrap();
    }
}
