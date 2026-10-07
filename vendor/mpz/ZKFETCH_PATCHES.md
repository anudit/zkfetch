# zkfetch patches to vendored mpz

Base: `v0.1.0-alpha.6` (6ebfe61). Only `mpz-common` is vendored.

## P1: single-threaded executor runner

`Executor::local_runner()` returns a `LocalRunner` whose `poll_run(cx, budget)`
drains the executor's global queue on the current thread. Scheduling a task
wakes the registered waker. Built with `num_threads(0)`, the executor spawns no
threads, so MPC runs inside a Cloudflare Worker (wasm32, no threads). The
threaded path is unchanged apart from one extra `AtomicWaker::wake` per
schedule.
