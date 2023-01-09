#![no_std]

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Buffer {
    pub size: usize,
}
