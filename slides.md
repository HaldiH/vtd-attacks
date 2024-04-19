---
theme: seriph
background: https://source.unsplash.com/collection/94734566/1920x1080
class: text-center
highlighter: shiki
lineNumbers: false
info: |
  ## Exploring Software Attacks on Intel VT-d Technology
  ### By [Hugo Haldi](https://haldih.github.io/)
drawings:
  persist: false
transition: slide-left
title: Exploring Software Attacks on Intel VT-d Technology
mdc: true
---

# Exploring Software Attacks on Intel VT-d Technology

A way to bypass the IOMMU protection mechanism

Based on the paper *[Software attacks against Intel VT-d technology](https://invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf)* by Rafal Wojtczuk and Joanna Rutkowska 

---

## Introduction

**What is a Virtual Machine ?**

<p v-click>
A virtual machine (VM) is an emulation of a computer system. It can run an operating system and applications just like a physical machine, but it is isolated from the underlying hardware.
</p>

<p v-click at="+1" style="font-weight: bold;">
What is a Virtual Machine Monitor (VMM), also known as a Hypervisor?
</p>

<p v-click at="+2">
A hypervisor is a software layer that allows multiple VMs to run on a single physical machine. It manages the VMs, allocates resources, and provides isolation between them.
</p>

---

### What is VT-d?

<p v-click>
Intel VT-d (Virtualization Technology for Directed I/O) is designed to improve virtualization performance by providing hardware assistance for virtualized I/O devices in the form of virtual I/O MMUs (IOMMUs).
</p>

<p v-click at="+1">
It allows the following:
</p>

<v-clicks>

- I/O device isolation: IOMMU can isolate I/O devices from each other and the host, allowing direct access to the device from the guest without interference from other VMs or the host.
- Improved performance: VT-d can lead to improved performance by reducing the overhead of virtualized I/O operations. It allows VMs to access I/O devices more directly, resulting in lower latency and better overall performance.
- DMA protection: IOMMU can protect the host memory from malicious DMA (Direct Memory Access) attacks by restricting the memory regions that an I/O device can access.
- Device assignment: VT-d facilitates device assignment, allowing VMs to have exclusive access to specific I/O devices. This can be particularly useful for high-performance I/O devices like GPUs or network cards.

</v-clicks>

---

## Attack scenario

The attacks we will focus on target *Driver Domains* (*domain* being a VM in this context). These domains are VMs that have direct access to I/O devices, such as network cards, disk controllers, or GPUs.

New hardware features such as Single Root I/O allow to natively share a single physical device between multiple domains. Hypervisors that support driver domains are Xen, VMWare ESXi, and KVM.

Driver domains are useful for both the server side and the client side. On the server side, they can be used to improve performance over traditional paravirtualized I/O. On the client side, they can be used to provide better security by isolating the I/O device from the rest of the system.

Some OSes, like Qubes OS, are specifically designed to use driver domains to improve security. A common use is gaming VMs, where the GPU is passed through to the VM to improve performance.

In the following attacks, we will attempt to gain full control over the host system, assuming that we have control over a driver domain, and the platform does not support Interrupt Remapping (true for all client systems before Sandy Bridge CPUs). These attacks have been conducted on a 64-bit Xen 4.0.1 hypervisor.

---

## Message Signaled Interrupts (MSI)

The attack relies on the fact that we can force a device to generate an MSI, which is not subject to the IOMMU protection mechanism. This allows us to bypass the IOMMU and gain access to the host memory.

Old systems used out-of-band mechanisms to signal interrupts, such as special pins and wires on the motherboard. Nowadays, most systems -especially those that use PCI-e interconnect- use an in-band mechanism, called MSI.

---

### MSI address format

From the device point of view, the MSI is a PCI-e memory write transaction that is destined to a specific address. Those addresses are recognized by the CPU as interrupts.

From the Intel SDM, the MSI format is as follows:

![MSI address format](/images/msi_address_format.png)

We can specify the CPU(s) that will receive the interrupt via the `Destination ID`, `RH`, and `DM` fields.

---

### MSI data format

Any PCIe writes transaction with `feeXXXXh` as the address results in an interrupt signal to one of the CPUs in the system.

<div class="two-column-div">

![MSI data format](/images/msi_data_format.png)

The two most important fields are:

- The `Vector` field specifies the interrupt number that will be signaled to the CPU.
- The `Delivery Mode` field specifies how the interrupt will be delivered to the CPU.

</div>

---

### Generating an MSI

MSI-based attacks are interesting since in most cases it is possible to perform such an attack without cooperating hardware (i.e. malicious device), using an innocent device, such as an integrated NIC.

MSI-capable PCIe devices contain special registers in their PCI configuration space that allow configuring the MSI address and data, meaning that system software can configure any MSI-capable device to generate any type of MSI, with arbitrary `vector` and `delivery mode`.

However, some hypervisors, such as Xen, may restrict driver domains from fully configuring assigned devices configuration space.

But no worries, each device has a database of per-device *quirks*, i.e. configuration space registers listing, to which the guest should have write access. Furthermore, we can set the `permissive` flag to the Xen PCI backend, allowing the guest to write to any configuration space register.

---

#### Generating an MSI without access to the device configuration space

It is also possible to generate MSI without access to the device configuration space, by using the `Scatter Gather` mechanism, which allows splitting one DMS transaction into several smaller ones, each with a different address.

The idea is to use this mechanism to generate a 4-byte memory write transaction that will be destined to the MSI address (`0xFEEXXXXX`).

C.f. [the paper](https://invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf) for more details.

---

## The SIPI attack

SIPI (Startup Inter-Processor Interrupt) is used by the BIOS to initialize all the CPUs in the system. When a system boots, only one CPU is active, called the BSP (Bootstrap Processor). The BIOS then sends a SIPI to all the other CPUs to wake them up.

The Intel documentation specifies that a SIPI interrupt can be delivered via programming the LAPIC (Local Advanced Programmable Interrupt Controller) register, called *Interrupt Command Register* (ICR), and are mapped into physical address space (typically starting at `0xFEE00000`).

---

### Using MSI to deliver a SIPI

<div class="two-column-div">

![ICR register](/images/icr_register.png)

The ICR register has common fields with the MSI data format, such as the `Vector` and `Delivery Mode` fields.

The *Start Up* delivery mode is not present in the MSI data format. The value `0b110`, which is used for SIPI in MSI packets, corresponds to `Reserved` in the MSI packet documentation.

So what would happen if we send an MSI with the `Delivery Mode` set to `0b110` (forbidden)?

<v-click>
The CPU will interpret it as a SIPI interrupt being delivered to one of the CPUs!
</v-click>

<p v-click at="+1">
MSI packets can additionally specify a `Vector` field, which is interpreted as part of a physical address where the receiving CPU should start executing code.
</p>

</div>

---

### Consequence

We can restart one of the CPUs in the system, and make it execute arbitrary code from an arbitrary address (limited to `0xVV000`), meaning that if an attacker managed to put a shellcode below the 1MB range, he can execute it, and gain access to the full system memory, e.g. all processes of VMs memory.

However, it is quite difficult to find meaningful instructions in the physical memory below 1MB, starting at page boundaries. This is a system-software-specific challenge, but not impossible.

---

### Mitigations

Inter CPUs block INIT interrupt when a CPU is in the VMX root mode (VT-x). However, INIT and SIPI interrupts are remembered and delivered when the CPU exits the VMX root mode (reboot or shutdown).

If the OS or hypervisor doesn't clean the memory, the attacker's shellcode will be able to steal data that remains in DRAM.

Shellcode will be executed with high permissions, so it can spawn additional attacks (BIOS flash, TXT bypassing, ...).

However, if the system runs in the SMX mode, an INIT interrupt causes immediate platform shutdown if outside of VMX: the attack doesn't work against TXT-loaded systems.

---

## Syscall injection attack

<div class="two-column-div">

![Syscall injection attack](/images/syscall_injection_attack.png)

We will use MSI attack to inject syscall or hypercall interrupt vector, in particular on Xen hypervisor.

When the CPU gets an interrupt with a such vector, it assumes that it's been issued by an active domain. If the interrupt is delivered when *Dom0* is active on the CPU, Xen will think that *Dom0* issued the hypercall and the permission context will be *Dom0*.

If we achieve to inject some hypercall, such as `do_domctl` with the `XEN_DOMCTL_set_target` subcommand, we can grant control rights over one domain to another, making the attacker driver domain super-privileged in *Dom0*.

</div>

---

### Register values

How to ensure proper values of some registers at the moment when the interrupt arrives?

Might be possible to find some backend process running in *Dom0* where the registers will be conveniently set. Timing is also crucial, as the registers are set only for a short period of time.

Furthermore, every hardware interrupt handler resets the *End of Interrupt* (EOI) register in the LAPIC, but software-generated interrupts are not expected to be used for servicing hardware interrupts, thus the EOI register is not reset.

In consequence, after injecting a hypercall interrupt, the LAPIC will be expecting to clear the EOI register, blocking all subsequent hypercall interrupts until the EOI register is cleared.

---

### Feasibility

The attack is not very practical, as it requires a lot of timing and luck. It still is a good example of how MSI attacks can be used to inject interrupts into the system.

However, this attack could be reliably used in practice to escape from a driver domain on an Xen system.

---

## The #AC injection attack

Exploits a similar problem in x86 architecture as the syscall injection attack.

We try to confuse the CPU about the stack layout that the exception handler expects to see.

An MSI with vector `0x11`, corresponds to `#AC` (Alignment Check) exception, which is quite convenient since it meets two requirements:

- Has a vector number greater than 15, so it can be delivered via MSI
- Is interpreted as an exception that stores an error code on the stack

---

### The attack

<div class="two-column-div">

![Exception handler VS. hardware interrupt stack layout](/images/exception_vs_interrupt_stack_layout.png)

If we deliver an MSI with vector `0x11`, it will trigger #AC handler execution on the target CPU.

The handler expects the error code to be placed at the top of the stack, thus misinterpreting all other stack values.

Thus CS placed by the CPU will be interpreted as RIP, RFLAGS as CS, and so on.

When the handler returns, it executes an IRET instruction that pops the previously saved register values from the stack and jumps back to CS:RIP, which actually the RFLAGS:CS address instead.

</div>

---

### Exploitation

RFLAGS can be controlled in the guest, so we can set RFLAGS so that it looks like a valid privileged CS segment selector.

CS that was stored on the stack (and now interpreted as RIP) has been stored by the CPU, but we know that is a 16-bit register, which is translated to a small number when interpreted as RIP. We can use `mmap()` to allocate memory in the guest and place arbitrary instructions at the virtual address pointed by the CS pointer.

We can raise high privileges in RFLAGS, and execute the shell code in the guest with hypervisor privileges in Xen.

This attack is mitigated by VMX guest mode though, because of the limited ability to control the address space and selectors in the root mode.

The exploitation might be mitigated by the implementation of the exception handler, e.g. by halting the system when an exception is raised, instead of trying to resume the execution. The attack might be limited only to para-virtualized guests.

---

## Practical MSI attack on Xen

The previous attacks we have seen seemed somehow mitigated by various, ofter accidental circumstances. So let's see how we could turn these theoretical attacks into a practical one.

Here is a fragment of the `copy_from_user()` function used by Xen hypercall handlers for accessing the hypercall arguments:

```asm
; rax – len of data to copy from usermode
; rsi – source buffer
; rdi – destination bufer
mov       %rax,%rcx
shr       $0x3,%rcx             ; rcx = len/8
and       $0x7,%rax
rep movsq %ds:(%rsi),%es:(%rdi) ; slow operation
mov       %rax,%rcx             ; rcx = len % 8
rep movsb %ds:(%rsi),%es:(%rdi)
```

The `rep movsq` instruction is a copy execution that executes `rcx` times.

Let's assume the source operand points to a slow memory, such as some MMIO of a device.

---

### The attack

Let's imagine that the attacker issued a hypercall from a driver domain. The input arguments for the hypercall were chosen to point to a virtual address in the attacker's domain that is mapped to the MMIO memory of a device that has been assigned to the driver domain.

The paper states that 80% to 90% of the time is spent in the `rep movsq` instruction in a such case. In the meantime, the attacker can issue an MSI, and the chances of it being delivered at the time when the processor is executing `rep movsq` are quite high.

Let's assume the MSI the attacker is generating is also for vector `0x82`, the original hypercall handler will be interrupted at the `rep movsq` instruction, and the processor will execute another instance of the hypercall handler to handle the fake hypercall. The CPU will save and restore all the CPU registers, so this should not affect the previous instance of the hypercall handler.

However, the hypercall returns status in the `rax` register, which means this register will be modified by the execution of this additional hypercall. When the original hypercall handler resumes, the value of `rax` will be different, and will likely contain the value of `-ENOSYS`, which will be interpreted as a very large number.

---

### Consequence

The `rep movsq` instruction will not be affected, but the instruction after, that copies `rax` to `rcx`, and the `rep movsb` instruction that is supposed to copy the remaining bytes, will be affected. The latter will copy a large number of bytes, causing a big overflow past the `rdi` address.

This would crash Xen, so we have to stop the copy operation before the huge `rcx` gets zeroed. A way to stop the copy would be to place an unmapped page directly after the input buffer, once the `rep movsb` instruction tries to access it, it will trigger a #PF (Page Fault) exception, which will stop the copy operation.

This is not enough though, as the #PF handler detects that the #PF was raised inside `copy_from_user()`, and will try to complete the copy by writing zeros to the destination buffer.

The attacker can overwrite the IDT (Interrupt Descriptor Table) to point to the attacker's shellcode, then when the overflowing continues, the #PF will be sooner or later raised, and the attacker's shellcode will be executed.

For this attack to work, the IDT must be located below the address pointed by the `rdi` register, and not too far away from it.

---
layout: image
image: /images/xen_msi_attack.png
backgroundSize: contain
---

### Mastering the overflow

We are now able to trigger an overflow inside the Xen hypervisor, starting from the address held in the `rdi` register. It turned out that just after the Xen stack, there is *often* the IDT, which is a perfect target for the overflow.

However, the exact location of the IDT table depends on whether we're on the BSP or an AP. In the first case, the IDT is allocated as part of the `.bss` section and is always after the BSP stack, at approx. 48 pages below. In the second case, the IDT is located right after the Xen stack, but this is not always the case, because the stack and IDT are allocated from the heap.

Thus, if we're unlucky, the IDT might be located above the stack, and the attacker won't be able to overwrite it.

---

### Exploiting the IDT

The exploit has two modes of operation: BSP and AP.

- In the BSP mode (domains execute on CPU #0), the exploit uses the 48 pages of padding in the payload, being the distance between the `rdi` register and the IDT. The shellcode is executed as #PF handler.
- In the AP mode, let's assume we're on CPU #1. The exploit uses 1 page of padding (on Q45 systems, depending on heap allocation layout)

The attacker has to figure out on which physical CPU the untrusted domain is running, and there is no easy way to do that. We can use one of the following approaches:

- Try to iteratively deliver MSIs to all CPUs, while keeping the hypercall trigger from the driver domain;
- Combine the "1-page" and "48-page" payloads in one universal payload.

One last problem is that there is no guarantee that we won't be moved to another CPU while generating the MSIs. Nevertheless, vCPU migration is not very frequent.

---

## Mitigating the attacks

---

### Interrupt Remapping

Intel has introduced a new feature called Interrupt Remapping (since Sandy Bridge processors, Q1 2011, and before with Xeon processors), which seems capable of protecting against the MSI attacks we've seen.

When Interrupt Remapping is enabled, interrupts can be blocked and/or translated, depending on their originating device. The remapping tables are filled to list all allowed interrupt vectors and formats available for each device.

---
layout: center
---

![MSI interrupt remapping format](/images/msi_interrupt_format.png)

---

#### MSI interrupt remapping format

The difference between the new format and the old one is that the new format doesn't directly specify any properties of the generated MSI, but rather only a field `handle` is specified, which is interpreted as an index in the interrupt remapping table, managed by the hypervisor.

This way, the device shouldn't be able to generate MSIs with e.g. arbitrary vectors.

However, some devices might not support the new format, so a compatibility format is available. In this case, the system is still vulnerable to the MSI attacks.

On his side, the hypervisor configures the interrupt remapping tables as follows:

- Allocates an Interrupt Vector in the global IDT for each device
- Adds an entry to the Interrupt Remapping Table for this device
- Writes to the device's configuration space registers for MSI

---

## Conclusion

We've seen that the Intel VT-d technology while providing many benefits, can be vulnerable to software attacks that can bypass the IOMMU protection mechanism.

The practical MSI attack on the Xen hypervisor depends on its specific implementation, however, it shows that a small vulnerability in the hypervisor can be exploited to gain full control over the host system.

The introduction of Interrupt Remapping in newer Intel processors seems to mitigate the attacks we've seen, but it is important to be aware of the potential security risks associated with VT-d technology.

---

## References

- *[Software attacks against Intel VT-d technology](https://invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf)* by Rafal Wojtczuk and Joanna Rutkowska


---
layout: center
---

## Thank you for your attention!

---
layout: end
---
