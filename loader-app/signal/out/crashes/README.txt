Command line used to find this crash:

/home/arslan/Documents/afl-head/AFL/afl-fuzz -Q -m 20000000000000 -i ./in/ -o ./out/ /home/arslan/Documents/qemusgx/loader-app/loader

If you can't reproduce a bug outside of afl-fuzz, be sure to set the same
memory limit. The limit used for this fuzzing session was infty.

Need a tool to minimize test cases before investigating the crashes or sending
them to a vendor? Check out the afl-tmin that comes with the fuzzer!

Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop
me a mail at <lcamtuf@coredump.cx> once the issues are fixed - I'd love to
add your finds to the gallery at:

  http://lcamtuf.coredump.cx/afl/

Thanks :-)
