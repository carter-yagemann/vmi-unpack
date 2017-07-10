# VMI-Unpack

## About

VMI-Unpack is a virtual machine introspection (VMI) based generic unpacker. Its
design is inspired by projects like [Ether](http://ether.gtisc.gatech.edu/) and
[DRAKVUF](https://github.com/tklengyel/drakvuf).

VMI-Unpack is intended for reverse engineering binaries that are obfuscated with
a technique known as packing. Unlike Ether, VMI-Unpack leverages actively
maintained projects like [libVMI](https://github.com/libvmi/libvmi) and
[rekall](https://github.com/google/rekall). Compared to Ether, which has been
stuck supporting only Xen 4.3 for over a decade, VMI-Unpack should be
significantly easier to maintain and extend.

VMI-Unpack is also MIT licensed so everyone can use and modify it.

## Support

VMI-Unpack current works under the following conditions:

Hypervisors:
* Xen
* KVM

Host OS:
* Linux

Virtual Machine OS:
* Windows
* Linux

Paging Modes:
* IA32E

## Installation

VMI-Unpack depends on [libVMI](https://github.com/libvmi/libvmi) and
[rekall](https://github.com/google/rekall), so these must be installed and
configured first along with a compatible hypervisor. You will also have to make
a libVMI configuration and rekall JSON profile for the virtual machine you wish
to perform unpacking on. Refer to both projects for more details.

VMI-Unpack additionally depends on the glib-2.0, json-glib-1.0, and the standard
built utilities. The following is an example of how to install these
dependencies on Debian using apt-get:

    sudo apt-get install build-essential libglib2.0-dev libjson-glib-dev

Once all the dependencies are installed, simply download or clone this
repository and run `make`.

## Usage

```
./bin/unpack [options]

Required arguments:
    -d <domain_name>         name of VM to unpack from
    -r <rekall_file>         path to rekall file
    -o <output_dir>          directory to dump layers into

One of the following must be provided:
    -p <pid>                 unpack process with provided PID
    -n <process_name>        unpack process with provided name

Optional arguments:
    -f                       also follow children created by target process
```

## Output

The current output of VMI-Unpack is very basic. Every time the target process
writes data to a page and then executes it, that page will be extracted as a
layer. Layers are written to the provided output directory in the form
`<pid>-<layer>-<rip>.bin` where `<layer>` starts at 0 and increments with each newly
extracted layer and `<rip>` is the value of the program counter when the layer
is first executed. This value can also be interpreted as the virtual address
the layer starts at.
