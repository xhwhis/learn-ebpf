#![no_std]

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Buffer {
    pub size: usize,
}
