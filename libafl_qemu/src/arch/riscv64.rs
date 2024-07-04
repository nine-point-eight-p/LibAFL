use std::sync::OnceLock;

use capstone::arch::BuildsCapstone;
use enum_map::{enum_map, EnumMap};
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "python")]
use pyo3::prelude::*;
pub use strum_macros::EnumIter;
pub use syscall_numbers::x86_64::*;

use crate::{sync_exit::ExitArgs, CallingConvention, QemuRWError, QemuRWErrorKind};

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter)]
#[repr(i32)]
pub enum Regs {
    Zero = 0,
    Ra = 1,
    Sp = 2,
    Gp = 3,
    Tp = 4,
    T0 = 5,
    T1 = 6,
    T2 = 7,
    S0 = 8,
    S1 = 9,
    A0 = 10,
    A1 = 11,
    A2 = 12,
    A3 = 13,
    A4 = 14,
    A5 = 15,
    A6 = 16,
    A7 = 17,
    S2 = 18,
    S3 = 19,
    S4 = 20,
    S5 = 21,
    S6 = 22,
    S7 = 23,
    S8 = 24,
    S9 = 25,
    S10 = 26,
    S11 = 27,
    T3 = 28,
    T4 = 29,
    T5 = 30,
    T6 = 31,
    Pc = 32, // Only for read/write PC
}

static EXIT_ARCH_REGS: OnceLock<EnumMap<ExitArgs, Regs>> = OnceLock::new();

pub fn get_exit_arch_regs() -> &'static EnumMap<ExitArgs, Regs> {
    EXIT_ARCH_REGS.get_or_init(|| {
        enum_map! {
            ExitArgs::Ret  => Regs::A0,
            ExitArgs::Cmd  => Regs::A0,
            ExitArgs::Arg1 => Regs::A1,
            ExitArgs::Arg2 => Regs::A2,
            ExitArgs::Arg3 => Regs::A3,
            ExitArgs::Arg4 => Regs::A4,
            ExitArgs::Arg5 => Regs::A5,
            ExitArgs::Arg6 => Regs::A6,
        }
    })
}

/// alias registers
#[allow(non_upper_case_globals)]
impl Regs {
    pub const Fp: Regs = Regs::S0;
}

#[cfg(feature = "python")]
impl IntoPy<PyObject> for Regs {
    fn into_py(self, py: Python) -> PyObject {
        let n: i32 = self.into();
        n.into_py(py)
    }
}

/// Return a RISC-V `ArchCapstoneBuilder`
#[must_use]
pub fn capstone() -> capstone::arch::riscv::ArchCapstoneBuilder {
    capstone::Capstone::new()
        .riscv()
        .mode(capstone::arch::riscv::ArchMode::RiscV64)
}

pub type GuestReg = u64;

impl crate::ArchExtras for crate::CPU {
    fn read_return_address<T>(&self) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>,
    {
        self.read_reg(Regs::Ra)
    }

    fn write_return_address<T>(&self, val: T) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        self.write_reg(Regs::Ra, val)
    }

    fn read_function_argument<T>(&self, conv: CallingConvention, idx: u8) -> Result<T, QemuRWError>
    where
        T: From<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Read, CallingConvention::Cdecl, conv)?;

        let reg_id = match idx {
            0 => Regs::A0,
            1 => Regs::A1,
            2 => Regs::A2,
            3 => Regs::A3,
            4 => Regs::A4,
            5 => Regs::A5,
            6 => Regs::A6,
            7 => Regs::A7,
            r => {
                return Err(QemuRWError::new_argument_error(
                    QemuRWErrorKind::Read,
                    i32::from(r),
                ))
            }
        };

        self.read_reg(reg_id)
    }

    fn write_function_argument<T>(
        &self,
        conv: CallingConvention,
        idx: i32,
        val: T,
    ) -> Result<(), QemuRWError>
    where
        T: Into<GuestReg>,
    {
        QemuRWError::check_conv(QemuRWErrorKind::Write, CallingConvention::Cdecl, conv)?;

        let val: GuestReg = val.into();
        match idx {
            0 => self.write_reg(Regs::A0, val),
            1 => self.write_reg(Regs::A1, val),
            r => Err(QemuRWError::new_argument_error(QemuRWErrorKind::Write, r)),
        }
    }
}
