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
What is a Virtual Machine Monitor (VMM), also known as a Hypervisor ?
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

- I/O device isolation: IOMMU can isolate I/O devices from each other and from the host, allowing direct access to the device from the guest without interference from other VMs or the host.
- Improved performance: VT-d can lead to improved performance by reducing the overhead of virtualized I/O operations. It allows VMs to access I/O devices more directly, resulting in lower latency and better overall performance.
- DMA protection: IOMMU can protect the host memory from malicious DMA (Direct Memory Access) attacks by restricting the memory regions that an I/O device can access.
- Device assigmment: VT-d facilitates device assignment, allowing VMs to have exclusive access to specific I/O devices. This can be particularly useful for high-performance I/O devices like GPUs or network cards.

</v-clicks>

---

## Attack scenario

The attacks we will focus on targets *Driver Domains* (*domain* being a VM in this context). These domains are VMs that have direct access to I/O devices, such as network cards, disk controllers, or GPUs.

New hardware features such as Single Root I/O allows to natively share a single physical device between multiple domains. Hypervisors that support driver domains are Xen, VMWare ESXi, and KVM.

Driver domains are useful for both a server side and a client side. In the server side, they can be used to improve performance over traditional paravirtualized I/O. In the client side, they can be used to provide better security by isolating the I/O device from the rest of the system.

Some OSes, like Qubes OS, are specifically designed to use driver domains to improve security. A common use are gaming VMs, where the GPU is passed through to the VM to improve performance.

In the following attacks, we will attempt to gain full control over the host system, assuming that we have control over a driver domain, and the platform does not support Interrupt Remapping (true for all client systems before Sandy Bridge CPUs). These attacks has been conducted on a 64-bit Xen 4.0.1 hypervisor.

---

## Message Signaled Interrupts (MSI)

The attacks relies on the fact that we can force a device to generate an MSI, which is not subject to the IOMMU protection mechanism. This allows us to bypass the IOMMU and gain access to the host memory.

Old systems used out-of-band mechanisms to signal interrupts, such as specian pins and wires on the motherboard. Nowadays, most systems -especially those which use PCI-e interconnect- use in-band mechanism, called MSI.

---

### MSI address format

From the device point of view, the MSI is a PCI-e memory write transaction that is destinated to a specific address. Those addresses are recognized by the CPU as interrupts.

From the Intel SDM, the MSI format is as follows:

![MSI address format](/images/msi_address_format.png)

We can specify the CPU(s) that will receive the interrupt via the `Destination ID`, `RH` and `DM` fields.

---

### MSI data format

Any PCIe write transaction with `feeXXXXh` as the address results in an interrupt signaled to one of the CPUs in the system.

<div class="two-column-div">

![MSI data format](/images/msi_data_format.png)

The two most important fields are:

- The `Vector` field specifies the interrupt number that will be signaled to the CPU.
- The `Delivery Mode` field specifies how the interrupt will be delivered to the CPU.

</div>

---

### Generating an MSI

MSI-based attacks are interesting since in most cases it is possible to perform such an attach without cooperating hardware (i.e. malicious device), using an innocent device, such as an integrated NIC.

MSI-capable PCIe devices contains special registers in its PCI configuration space that allows to configure the MSI address and data, meaning that system software can configure any MSI-capable device to generate any type of MSI, with arbitrary `vector` and `delivery mode`.

However, some hypervisors, such as Xen, may restrict driver domains from fully configuring assigned devices configuration space.

But no worries, each device has a database of per-device *quirks*, i.e. configuration space registers listing, to which the guest should have write access. Furthermore, we can set the `permissive` flag to the Xen PCI backend, allowing the guest to write to any configuration space register.

---

#### Generating an MSI without access to the device configuration space

It is also possible to generate MSI without access to the device configuration space, by using the `Scatter Gather` mechanism, that allows splitting one DMS transaction into several smaller ones, each with a different address.

The idea is to use this mechanism to generate a 4-byte memory write transaction that will be destinated to the MSI address (`0xFEEXXXXX`).

C.f. [the paper](https://invisiblethingslab.com/resources/2011/Software%20Attacks%20on%20Intel%20VT-d.pdf) for more details.

---

## The SIPI attack

SIPI (Startup Inter-Processor Interrupt) is used by the BIOS to initialize all the CPUs in the system. When a system boots, only one CPU is active, called the BSP (Bootstrap Processor). The BIOS then sends a SIPI to all the other CPUs to wake them up.

