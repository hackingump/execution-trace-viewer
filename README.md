# x64DbgTraceTools

This fork is simply to extract the parser from the original `execution-trace-viewer` by `teemu-I`.

There are just some small modifications I did in order for it to be useable by Triton. 
None of the code is mine and I give full credit to `teemu-I` for this.

## My modifications

* Return opcodes in byte instead of string
* Move core and main parsing function into one file
