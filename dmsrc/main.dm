// rust_g.dm - DM API for rust_g extension library
//
// To configure, create a `rust_g.config.dm` and set what you care about from
// the following options:
//
// #define RUST_G "path/to/rust_g"
// Override the .dll/.so detection logic with a fixed path or with detection
// logic of your own.
//
// #define RUSTG_OVERRIDE_BUILTINS
// Enable replacement rust-g functions for certain builtins. Off by default.

#ifndef RUST_G
// Default automatic RUST_G detection.
// On Windows, looks in the standard places for `rust_g.dll`.
// On Linux, looks in `.`, `$LD_LIBRARY_PATH`, and `~/.byond/bin` for either of
// `librust_g.so` (preferred) or `rust_g` (old).

/* This comment bypasses grep checks */ /var/__rust_g

/proc/__detect_rust_g()
	var/arch_suffix = null
	#ifdef OPENDREAM
	arch_suffix = "64"
	#endif
	if (world.system_type == UNIX)
		if (fexists("./librust_g[arch_suffix].so"))
			// No need for LD_LIBRARY_PATH badness.
			return __rust_g = "./librust_g[arch_suffix].so"
		else if (fexists("./rust_g[arch_suffix]"))
			// Old dumb filename.
			return __rust_g = "./rust_g[arch_suffix]"
		else if (fexists("[world.GetConfig("env", "HOME")]/.byond/bin/rust_g[arch_suffix]"))
			// Old dumb filename in `~/.byond/bin`.
			return __rust_g = "rust_g[arch_suffix]"
		else
			// It's not in the current directory, so try others
			return __rust_g = "librust_g[arch_suffix].so"
	else
		return __rust_g = "rust_g[arch_suffix]"

#define RUST_G (__rust_g || __detect_rust_g())
#endif

// Handle 515 call() -> call_ext() changes
#if DM_VERSION >= 515
#define RUSTG_CALL call_ext
#else
#define RUSTG_CALL call
#endif

/// Gets the version of rust_g
/proc/rustg_get_version() return RUSTG_CALL(RUST_G, "get_version")()
