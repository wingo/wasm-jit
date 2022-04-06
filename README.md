# WASI JIT workbench

This repo is for artifacts related to run-time code generation for
WebAssembly/WASI programs and components.

## Background

### What's the big idea?

Just-in-time (JIT) code generation is an important tactic when
implementing a programming language.  Generating code at run-time allows
a program to specialize itself against the specific data it is run
against.  For a program that implements a programming language, that
specialization is with respect to the program being run, and possibly
with respect to the data that program uses.

The way this typically works is that the program generates bytes for the
instruction set of the machine it's running on, and then transfers
control to those instructions.

Usually the program has to put its generated code in memory that is
specially marked as executable.  However, this capability is missing in
WebAssembly.  How, then, to do just-in-time compilation in WebAssembly?

### WebAssembly as a Harvard architecture

In a von Neumman machine, like the ones that you are probably reading
this on, code and data share an address space.  There's only one kind of
pointer, and it can point to anything: the bytes that implement the
`sin` function, the number `42`, the characters in `"biscuits"`, or
anything at all.  WebAssembly is different in that its code is not
addressable at run-time.  Functions in a WebAssembly module are numbered
sequentially from 0, and the WebAssembly `call` instruction takes the
callee as an immediate parameter.

So, to add code to a WebAssembly program, somehow you'd have to augment
the program with more functions.  Let's assume we will make that
possible somehow -- that your WebAssembly module that had N functions
will now have N+1 functions, and with function N being the new one your
program generated.  How would we call it?  Given that the `call`
instructions hard-code the callee, the existing functions 0 to N-1 won't
call it.

Here the answer is `call_indirect`.  A bit of a reminder, this
instruction take the callee as an operand, not an immediate parameter,
allowing it to choose the callee function at run-time.  The callee
operand is an index into a *table* of functions.  Conventionally, table
0 is called the *indirect call table* as it contains an entry for each
function which might ever be the target of an indirect call.

With this in mind, our problem has two parts, then: (1) how to augment a
WebAssembly module with a new function, and (2) how to get the original
module to call the new code.

### Late linking with Wizer

The key idea here is to build on
[Wizer](https://github.com/bytecodealliance/wizer)'s ability to take a
snapshot of a WebAssembly module.  We extend Wizer also to be able to
augment the module with new code.  In this role, Wizer is effectively a
late linker, linking in a new archive to an existing object.

System linkers like `ld` typically require a complete set of symbols and
relocations to resolve inter-archive references.  However when
performing a late link of JIT-generated code, we can take a short-cut:
the main program can embed memory addresses directly into the code it
generates.

So generated-to-main references don't need relocation.  However
main-to-generated references do need to be resolved by Wizer.

### Late linking appears to be async codegen

From the perspective of a main program, WebAssembly JIT code generation
via late linking appears the same as aynchronous code generation.

For example, take the C program:

```c
struct Value;
struct Func {
  struct Expr *body;
  void *jitCode;
}

struct Value* interpretCall(struct Expr *body,
                            struct Value *arg);

struct Value* call(struct Func *func,
                   struct Value* val) {
  if (func->jitCode) {
    struct Value* (*f)(struct Value*) = jitCode;
    return f(val);
  } else {
    return interpretCall(func->body, val);
  }
}
```

Here the C program allows for the possibility of JIT code generation:
there is a slot in a `Func` instance to fill in with a code pointer.  If
this program generates code for a given `Func`, it won't be able to fill
in the pointer -- it can't add new code to the image.  But, it could
tell Wizer to do so, and Wizer could snapshot the program, link in the
new function, and patch `&func->jitCode`.  From the program's
perspective, it's as if the code becomes available asynchronously.

### Protocol: WebAssembly modules

Finally, the question is, how does a program communicate to Wizer about
the set of functions to patch in, along with code locations to be
patched?  The approach we are taking is to have the program generate
full WebAssembly modules, as in the [Linking
convention](https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md#relocation-sections),
with relocation sections indicating the locations in the main binary to
patch.

## Usage

to be continued...
