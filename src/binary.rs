#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{fmt, usize};

#[cfg(feature = "elf")]
use checksec::elf;
#[cfg(feature = "macho")]
use checksec::macho;
#[cfg(feature = "pe")]
use checksec::pe;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BinType {
    #[cfg(feature = "elf")]
    Elf(u16), //u16 = machine type
    #[cfg(feature = "pe")]
    PE(u16), // u16 = machine type
    #[cfg(feature = "macho")]
    MachO(u32,u32), //u32 = cputype
}
#[cfg(not(feature = "color"))]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf(machine_type) => write!(f, "ELF_{}", goblin::elf::header::machine_to_str(machine_type)),
            #[cfg(feature = "pe")]
            Self::PE(machine_type) => write!(f, "PE_{}", goblin::pe::header::machine_to_str(machine_type)),
            #[cfg(feature = "macho")]
            Self::MachO(cputype, cpusubtype) => write!(f, "MachO_{}", goblin::mach::constants::cputype::get_arch_name_from_types(cputype, cpusubtype).unwrap_or("UNKNOWN")),
        }
    }
}
#[cfg(feature = "color")]
impl fmt::Display for BinType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            #[cfg(feature = "elf")]
            Self::Elf(machine_type) => write!(f, "{}{}", "ELF_".bold().underline(), goblin::elf::header::machine_to_str(machine_type).bold().underline()),
            #[cfg(feature = "pe")]
            Self::PE(machine_type) => write!(f, "{}{}", "PE_".bold().underline(), goblin::pe::header::machine_to_str(machine_type).bold().underline()),
            #[cfg(feature = "macho")]
            Self::MachO(cputype, cpusubtype) => write!(f, "{}{}", "MachO_".bold().underline(), goblin::mach::constants::cputype::get_arch_name_from_types(cputype, cpusubtype).unwrap_or("UNKNOWN").bold().underline()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BinSpecificProperties {
    #[cfg(feature = "elf")]
    Elf(elf::CheckSecResults),
    #[cfg(feature = "pe")]
    PE(pe::CheckSecResults),
    #[cfg(feature = "macho")]
    MachO(macho::CheckSecResults),
}
impl fmt::Display for BinSpecificProperties {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "elf")]
            Self::Elf(b) => write!(f, "{b}"),
            #[cfg(feature = "pe")]
            Self::PE(b) => write!(f, "{b}"),
            #[cfg(feature = "macho")]
            Self::MachO(b) => write!(f, "{b}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Blob {
    pub binarytype: BinType,
    pub properties: BinSpecificProperties,
}

impl Blob {
    pub fn new(
        binarytype: BinType,
        properties: BinSpecificProperties,
    ) -> Self {
        Self { binarytype, properties }
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Binary {
    pub file: PathBuf,
    pub blobs: Vec<Blob>,
    pub libraries: Vec<Binary>,
}

impl Binary {
    pub fn new(file: PathBuf, blobs: Vec<Blob>) -> Self {
        Self { file, blobs, libraries: vec![] }
    }
}
