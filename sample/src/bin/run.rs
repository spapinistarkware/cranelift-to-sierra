#![no_std]
#![no_main]

use core::arch::asm;
use sample::fib;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let res = fib(1);
    sys_exit(res as i32)
}

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

fn sys_exit(status: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60,
            in("rdi") status,
            options(noreturn)
        );
    }
}
