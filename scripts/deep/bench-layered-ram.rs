// SPDX-License-Identifier: Apache-2.0
//! Compare quiesced RAM rebase and restore read-ahead on a fixed local working set.
//! This host-side experiment uses libkrun's public Generation API.
use krun_vmm::{layered_restore::Generation, snapshot::MemoryRegionDesc};
use std::fs::File;
use std::hint::black_box;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::time::Instant;
use vm_memory::{Bytes, GuestAddress, GuestMemory};

const PAGE: usize = 4096;
const PAGES: usize = 4096;
const SIZE: usize = PAGE * PAGES;

fn readonly_file(data: &[u8]) -> File {
    let file = tempfile::tempfile().unwrap();
    file.write_all_at(data, 0).unwrap();
    file.sync_all().unwrap();
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
}

fn generation(file: &File, size: usize) -> Generation {
    Generation::from_immutable_file(
        &[MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }],
        file,
    )
    .unwrap()
}

fn contents() -> Vec<u8> {
    let mut data = vec![0u8; SIZE];
    for (index, page) in data.chunks_exact_mut(PAGE).enumerate() {
        page.fill((index % 251) as u8);
    }
    data
}

fn bytes_at(index: usize, dirty: bool) -> u8 {
    if dirty && index % 31 == 0 {
        0xfd
    } else {
        (index % 251) as u8
    }
}

fn sample(base: &Generation, dirty: bool, guarded: bool, prefetch: bool) {
    let live = base.restore().unwrap();
    if dirty {
        for index in (0..PAGES).step_by(31) {
            live.write_obj(0xfd_u8, GuestAddress((index * PAGE) as u64))
                .unwrap();
        }
    }
    let start = Instant::now();
    let (next, copied) = base.capture_quiesced(&live).unwrap();
    let capture = start.elapsed();
    let rebase_start = Instant::now();
    // Both generations stay alive and writers remain quiesced throughout this
    // decision. The serialized descriptors identify the same retained FDs,
    // offsets, extent lengths, guest addresses and process lifetime.
    let skip = guarded
        && copied == 0
        && base.encode_manifest().unwrap() == next.encode_manifest().unwrap();
    assert_eq!(skip, guarded && !dirty);
    if !skip {
        next.rebase_quiesced(&live).unwrap();
    }
    let rebase = rebase_start.elapsed();
    assert_eq!(copied, if dirty { PAGES.div_ceil(31) * PAGE } else { 0 });
    let task_start = Instant::now();
    let target = next.restore().unwrap();
    if prefetch {
        for index in (0..PAGES).step_by(8) {
            black_box(
                target
                    .read_obj::<u8>(GuestAddress((index * PAGE) as u64))
                    .unwrap(),
            );
        }
    }
    // Read the same 512 pages in a deterministic permutation in all groups.
    for round in 0..PAGES / 8 {
        let index = ((round * 127) % (PAGES / 8)) * 8;
        assert_eq!(
            target
                .read_obj::<u8>(GuestAddress((index * PAGE) as u64))
                .unwrap(),
            bytes_at(index, dirty)
        );
    }
    let first_task = task_start.elapsed();
    let sibling = base.restore().unwrap();
    for index in 0..PAGES {
        let address = GuestAddress((index * PAGE) as u64);
        let expected = bytes_at(index, dirty);
        assert_eq!(live.read_obj::<u8>(address).unwrap(), expected);
        assert_eq!(target.read_obj::<u8>(address).unwrap(), expected);
        assert_eq!(
            sibling.read_obj::<u8>(address).unwrap(),
            bytes_at(index, false)
        );
    }
    println!(
        "{dirty},{guarded},{prefetch},{copied},{},{},{}",
        capture.as_nanos(),
        rebase.as_nanos(),
        first_task.as_nanos()
    );
}

fn shared_file_cache() {
    let data = contents();
    let files = [readonly_file(&data), readonly_file(&data)];
    let bases = files.each_ref().map(|f| generation(f, SIZE));
    println!("shared_backing,resident_pages_before,checked_bytes,restore_and_task_ns");
    for round in 0..12 {
        for share in [round % 2 == 0, round % 2 != 0] {
            // Prior mappings have been dropped. The second file has identical
            // contents and an independent inode on the same filesystem.
            for file in &files {
                assert_eq!(
                    unsafe {
                        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED)
                    },
                    0
                );
            }
            let first = bases[0].restore().unwrap();
            for i in 0..PAGES {
                assert_eq!(
                    first
                        .read_obj::<u8>(GuestAddress((i * PAGE) as u64))
                        .unwrap(),
                    bytes_at(i, false)
                );
            }
            drop(first);
            let start = Instant::now();
            let second = bases[usize::from(!share)].restore().unwrap();
            let mapping_time = start.elapsed();
            let mut resident = vec![0u8; PAGES];
            // The only region covers this entire page-aligned mapping.
            let address = second.get_host_address(GuestAddress(0)).unwrap();
            assert_eq!(
                unsafe { libc::mincore(address.cast(), SIZE, resident.as_mut_ptr()) },
                0
            );
            let resident = resident.iter().filter(|value| **value & 1 != 0).count();
            let mut buffer = [0u8; PAGE];
            let task = Instant::now();
            for round in 0..PAGES / 8 {
                let index = ((round * 127) % (PAGES / 8)) * 8;
                second
                    .read_slice(&mut buffer, GuestAddress((index * PAGE) as u64))
                    .unwrap();
                assert!(buffer.iter().all(|byte| *byte == bytes_at(index, false)));
            }
            let elapsed = mapping_time + task.elapsed();
            println!("{share},{resident},{},{}", SIZE / 8, elapsed.as_nanos());
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn mixed_writers() {
    use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_regs, kvm_userspace_memory_region};
    use kvm_ioctls::{Kvm, VcpuExit};
    let mut data = vec![0u8; 16 * PAGE];
    // Real-mode guest writes its two assigned data pages, then halts.
    let program = [
        0xc6, 0x06, 0x00, 0x30, 0x41, 0xc6, 0x06, 0x00, 0x40, 0x42, 0xf4,
    ];
    data[..program.len()].copy_from_slice(&program);
    let base = generation(&readonly_file(&data), data.len());
    let live = base.restore().unwrap();
    let kvm = Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();
    // The owned mapping stays alive until after the vCPU halts and the VM closes.
    unsafe {
        vm.set_user_memory_region(kvm_userspace_memory_region {
            slot: 0,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
            guest_phys_addr: 0,
            memory_size: data.len() as u64,
            userspace_addr: live.get_host_address(GuestAddress(0)).unwrap() as u64,
        })
        .unwrap();
    }
    let mut cpu = vm.create_vcpu(0).unwrap();
    let mut sregs = cpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    sregs.ds.base = 0;
    sregs.ds.selector = 0;
    cpu.set_sregs(&sregs).unwrap();
    cpu.set_regs(&kvm_regs {
        rip: 0,
        rflags: 2,
        ..Default::default()
    })
    .unwrap();
    assert!(matches!(cpu.run().unwrap(), VcpuExit::Hlt));
    // The device-side writer also touches page four and independently writes page five.
    for (address, value) in [(0x4000, 0xd4u8), (0x5000, 0xd5u8)] {
        live.write_obj(value, GuestAddress(address)).unwrap();
    }
    let bitmap = vm.get_dirty_log(0, data.len()).unwrap();
    assert_ne!(bitmap[0] & (1 << 3), 0);
    assert_ne!(bitmap[0] & (1 << 4), 0);
    assert_eq!(bitmap[0] & (1 << 5), 0);
    drop(cpu);
    drop(vm);
    let (captured, copied) = base.capture_quiesced(&live).unwrap();
    assert_eq!(copied, 3 * PAGE);
    captured.rebase_quiesced(&live).unwrap();
    let child = captured.restore().unwrap();
    let sibling = base.restore().unwrap();
    for (address, expected) in [(0x3000, 0x41u8), (0x4000, 0xd4u8), (0x5000, 0xd5u8)] {
        let address = GuestAddress(address);
        assert_eq!(child.read_obj::<u8>(address).unwrap(), expected);
        assert_eq!(live.read_obj::<u8>(address).unwrap(), expected);
        assert_eq!(sibling.read_obj::<u8>(address).unwrap(), 0);
    }
    println!(
        "KVM dirty bitmap {:#x}, source and target retained all three pages, copied {copied} bytes",
        bitmap[0]
    );
}

fn main() {
    assert_eq!(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }, PAGE as i64);
    match std::env::args().nth(1).as_deref() {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        Some("--mixed-writers") => return mixed_writers(),
        Some("--shared-cache") => return shared_file_cache(),
        None => (),
        Some(argument) => panic!("unknown experiment: {argument}"),
    }
    let base = generation(&readonly_file(&contents()), SIZE);
    println!("dirty,guarded,prefetch,copied_bytes,capture_ns,rebase_ns,restore_and_task_ns");
    for round in 0..12 {
        for group in 0..8 {
            // Reverse trial order every round to distribute warm-cache effects.
            let group = if round % 2 == 0 { group } else { 7 - group };
            sample(&base, group & 4 != 0, group & 2 != 0, group & 1 != 0);
        }
    }
}
