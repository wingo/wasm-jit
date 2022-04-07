import time
from wasmtime import Engine, Store, Module, Instance, Func, FuncType, Linker, WasiConfig, Config
import wasmtime.loader
import interplib

wasi = WasiConfig()
wasi.inherit_stdout();
wasi.inherit_stderr();
wasmtime.loader.store.set_wasi(wasi)

# Explicitly initialize, as we build interplib as a WASI reactor, not a
# WASI command.
interplib._initialize()

# /opt/wasi-sdk/bin/clang++ -O2 -mexec-model=reactor -Wl,--growable-table -Wl,--export-table -DLIBRARY=1 -Wall -fno-exceptions interp.cc -o interplib.wasm && python3 interp.py

def fib_program(count):
    return f"""
(letrec ((fib (lambda (n)
               (if (< n 2)
                   1
                   (+ (fib (- n 1))
                      (fib (- n 2)))))))
  (fib {count}))
"""

def write_string(string):
    utf8 = string.encode('utf-8')
    ptr = interplib.allocateBytes(len(utf8) + 1)
    ptr = interplib.allocateBytes(len(utf8) + 1)
    dst = interplib.memory.data_ptr(wasmtime.loader.store)
    for i in range(0,len(utf8)):
        dst[ptr + i] = utf8[i]
    dst[ptr + len(utf8)] = 0
    return ptr

def free_string(ptr):
    interplib.freeBytes(ptr)

def parse(string):
    ptr = write_string(string)
    expr = interplib.parse(ptr)
    free_string(ptr)
    return expr

def eval(expr):
    return interplib.eval(expr, 1024 * 1024)

def jitModule():
    ptr = interplib.jitModule()
    if ptr == 0:
        return None
    data = interplib.moduleData(ptr);
    size = interplib.moduleSize(ptr);
    dst = bytearray()
    src = interplib.memory.data_ptr(wasmtime.loader.store)
    for i in range(0, size):
        dst.append(src[data +i])
    interplib.freeModule(ptr)
    return Module(wasmtime.loader.store.engine, dst)

fib_code = fib_program(30)

print(f'Parsing: {fib_code}')
fib_expr = parse(fib_code)
print(f'Parse result: {fib_expr:#x}')

print(f'Calling eval({fib_expr:#x}) 5 times')
start_time = time.time()
for i in range(0,5):
    eval(fib_expr)
print(f'Calling eval({fib_expr:#x}) 5 times took {time.time() - start_time}s.')

print('Calling jitModule()')
jit_module = jitModule()
print(f'jitModule result: {jit_module}')

wasmtime.loader.linker.define("env", "memory", interplib.memory)
wasmtime.loader.linker.define("env", "__indirect_function_table", interplib.__indirect_function_table)
print(f'Instantiating and patching in JIT module')
instance = wasmtime.loader.linker.instantiate(wasmtime.loader.store, jit_module)

print(f'Calling eval({fib_expr:#x}) 5 times')
start_time = time.time()
for i in range(0,5):
    eval(fib_expr)
print(f'Calling eval({fib_expr:#x}) 5 times took {time.time() - start_time}s.')
