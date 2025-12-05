BCH is computationally equivalent to ETH now, but BCH has significantly higher compute limits and lower fees. 

As of May 2025, almost anything can be compiled or ported to CashVM, and by May 2026, CashVM will effectively be a high-level language: arbitrary precision math, loops, functions, etc. In general, you can do anything with ECDSA-like compute density (CPU-per-byte) up to 100KB of code/data (in standard transactions, 1MB nonstandard). Pay for a bigger transaction, get more compute.

(Re 2026 upgrade: many BCH stakeholders have already published lock-in approval statements – one of the 4 CHIPs had some contention earlier, but the disputing stakeholders have now endorsed that CHIP too. At this point, probably only discovery of an unfixable flaw would delay any of the 2026 CHIPs. Note that Nov 15 is the lock-in date + "chipnet" 6-month-early network upgrade, so after Nov 15, we'll be certain about which CHIPs are going into the May 2026 BCH upgrade.)

For a demo, here's the LM-OTS post-quantum signature scheme implemented precisely according to RFC 8554 (NIST adopted) in pure Bitcoin (Cash) Script: https://blog.bitjson.com/quantumroot/. It's >2x more byte efficient than the WASM equivalent (I'll share more comparing them later)

And performance wise, this is an example that e.g. is not possible to build on Solana. I wrote a bit more about that here: https://bitcoincashresearch.org/t/chip-2025-08-functions-takes-2-3/1656/48#protocol-complexity-overhead-of-mutation-tracking-9, but TLDR: Solana's compute limits are too low per-byte + Solana's maximum transaction size is too small.

BCH transaction validation is "embarrassingly parallel" to an absurd degree, so we were able to clean up the limits over the past few years to actually reduce the worst case validation performance from pre-2017 requirements (i.e. BTC nodes need higher specs than BCH nodes today) while expanding contract capabilities to ETH levels. 

BCH re-enabled many of the Satoshi opcodes + data signatures (from the stack) in 2018, a full set of introspection opcodes in 2022, native token primitives in 2023, and arbitrary precision math in 2025. The 2026 upgrade mainly improves code-factoring (trimming waste/duplication) vs. adding new capabilities.

I picked that LM-OTS scheme as a technical demo since it hits several critical thresholds vs. ETH and SOL. On BCH, these Quantumroot transactions are actually faster-to-validate-per-byte than "payments only" Bitcoin Cash transactions have been since 2009 (and likewise vs. BTC transactions).

Re screenshot: is an in-browser IDE (
@BitauthIDE
) I've built over the past few years. I'll be working a lot more on it this year (finally) now that CashVM is relatively feature complete – there's a lot more multi-transaction system design, invariant testing, constraint solving, symbolic execution, etc. capabilities I'd like to add.

Re BCH opcodes: not sure if there are any websites with pretty tables (maybe I should build one), but here's a full listing with descriptions I wrote – today's opcodes (last addition 2023): https://github.com/bitauth/libauth/blob/61abaca37bc86cccce5fa99c86a48f0c8793643f/src/lib/vm/instruction-sets/bch/2023/bch-2023-descriptions.ts and the 2026 additions (loops, functions, and some additional bitwise ops): https://github.com/bitauth/libauth/blob/0534f9bb063c438ffac0880bc5413feae6f66b77/src/lib/vm/instruction-sets/bch/2026/bch-2026-descriptions.ts

Re language: Bitauth IDE includes a very basic language and compiler I call "CashAssembly" that compiles to CashVM bytecode – it's just a way of writing raw data and opcodes with some basic variable support and other features. It's essentially what you see on the old Bitcoin wiki, but with some lossiness cleaned up.

The BCH space has other high-level languages too – CashScript is a JS-like stack (loops pending: https://github.com/CashScript/cashscript/issues/246#issuecomment-3304112773) and AlbaDsl is a really promising Haskell DSL. 

Remember though that Satoshi based the Bitcoin Script language on Forth (a high-level language of its own) – it's honestly great for building substantial applications from many small modules.

For heavy applications like ZK proof verification, it's hard to beat the low-level control of CashAssembly right now. I made lots of performance improvements to Bitauth IDE while working on Quantumroot, and I'll be happy to help fix any perf issues as your application grows.

Bitauth IDE has lots of built-in testing capabilities too, so I'm happy to help you set up "tested scripts" with scenarios and such. I wrote more about testing CashAssembly here recently: https://t.me/bitauth_ide/1627



https://github.com/CashScript/cashscript/issues/246#issuecomment-3304112773

Just leaving a note after chatting with @mr-zwets and @rkalis on this – CashScript is well positioned to be one of the most-well-adapted languages for CashVM.

Many other projects will ultimately find ways to adapt their existing language/compiler/tooling to target CashVM, producing compiled artifacts at various levels of sub-optimal (introducing workarounds and emulations to expose the kind of API they expect to programs within their artifacts – e.g. how emscripten or Rust produce some consistent overhead in their WASM-compiled artifacts).

Compared to these, CashScript is uniquely unburdened by existing features/patterns that were adapted to non-CashVM environments. Over time, CashScript will be a great place for companies to contribute optimizations and improvements that make it better even than hand-written CashVM bytecode, since compilers can usually attempt a vast number of potential optimizations that raw bytecode authors are less likely to use in perfectly-optimal combination(s). (This is why compilers have long outperformed hand-written assembly in sufficiently complex programs. Hand optimization is great for small components – and designing the actual compiler optimization techniques, but past some level of complexity, only a compiler can apply those optimizations optimally to very large programs.)

At a high level, that means for projects being ported from Rust, LLVM source languages, etc. "just rewrite it in CashScript" could ultimately be the best solution for many projects looking to get to the leanest, most auditable, production CashVM bytecode. And likewise for AlbaDsl or any other BCH-first smart contract systems.

So: counterintuitively, I'd encourage CashScript to start as low-level as possible on new features like this. For loops, that probably means a begin {} until (...) loop – a construction that can be directly translated with zero overhead or emulation tricks. I'd even encourage you to directly use the begin/until syntax – rather than designing your own e.g. loop {} until (...) – since the intention is to offer a lowest-level hook, and CashScript devs recognizing the begin as directly mapping to an OP_BEGIN eliminates some potential for magical thinking. (And note that the Forth world already uses the begin/until syntax – there's a multi-decade history of this syntax being maximally-useful to humans writing the actual source code. E.g. using loop as a keyword is likely to create real confusion vs. do/loop syntax.)

Of course, IMO CashScript should continue to focus on being user-friendly for new CashScript developers, and it would be perfectly reasonable for CashScript to also offer other loop constructions that average users expect (esp. for-style with initialization and a conditional check at the "top" of the loop and do/while, which is simply begin/until with the condition check inverted.)

However, those higher-level constructions should reasonably take more time to "get right" (maybe staying in a beta version for a little longer), whereas begin/until loops are very low risk at a language level – in the same way that TypeScript can very safely add Stage 4 Javascript features.