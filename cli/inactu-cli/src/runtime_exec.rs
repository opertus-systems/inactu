use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

use crate::constants::{
    WASM_FUEL_LIMIT, WASM_INSTANCES_LIMIT, WASM_MEMORIES_LIMIT, WASM_MEMORY_LIMIT_BYTES,
    WASM_TABLES_LIMIT, WASM_TABLE_ELEMENTS_LIMIT,
};

struct HostState {
    limits: StoreLimits,
}

pub fn execute_wasm(wasm: &[u8], entrypoint: &str) -> Result<Vec<u8>, String> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|e| format!("wasm engine init failed: {e}"))?;
    let module =
        Module::from_binary(&engine, wasm).map_err(|e| format!("invalid wasm module: {e}"))?;
    let host_state = HostState {
        limits: StoreLimitsBuilder::new()
            .memory_size(WASM_MEMORY_LIMIT_BYTES)
            .table_elements(WASM_TABLE_ELEMENTS_LIMIT)
            .instances(WASM_INSTANCES_LIMIT)
            .tables(WASM_TABLES_LIMIT)
            .memories(WASM_MEMORIES_LIMIT)
            .build(),
    };
    let mut store = Store::new(&engine, host_state);
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(WASM_FUEL_LIMIT)
        .map_err(|e| format!("wasm fuel configuration failed: {e}"))?;
    let linker = Linker::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("wasm instantiation failed: {e}"))?;

    if let Ok(func) = instance.get_typed_func::<(), i32>(&mut store, entrypoint) {
        let result = func.call(&mut store, ()).map_err(|e| {
            if matches!(store.get_fuel(), Ok(0)) {
                format!("wasm execution failed: fuel exhausted: {e}")
            } else {
                format!("wasm execution failed: {e}")
            }
        })?;
        return Ok(result.to_string().into_bytes());
    }
    if let Ok(func) = instance.get_typed_func::<(), ()>(&mut store, entrypoint) {
        func.call(&mut store, ()).map_err(|e| {
            if matches!(store.get_fuel(), Ok(0)) {
                format!("wasm execution failed: fuel exhausted: {e}")
            } else {
                format!("wasm execution failed: {e}")
            }
        })?;
        return Ok(Vec::new());
    }

    Err(format!(
        "entrypoint not found with supported signature (() -> i32 | ()) : {entrypoint}"
    ))
}
