initSidebarItems({"fn":[["from_hex","Decode a hex string into bytes."],["to_base64","Encode an utf8 string to a base64 string"],["to_hex","Encode the provided bytes into a hex string"]],"macro":[["impl_array_newtype","gives a newtype array wrapper standard array traits"],["impl_array_newtype_encodable","gives a newtype array wrapper serialization and deserialization methods"],["impl_array_newtype_show","gives a newtype array wrapper the Debug trait"],["impl_index_newtype","gives a newtype array wrapper Index traits"]],"mod":[["file","File util"],["logger","Logging wrapper to be used throughout all crates in the workspace"],["macros","Macros to support Rust BIP-32 code (though could conceivably be used for other things)"],["read_write","Custom impls of read_exact and write_all to work around async stream restrictions."],["secp_static","Globally accessible static instance of secp256k1, to avoid initialization overhead"],["types","Logging configuration types"],["zip","Compress and decompress zip bz2 archives"]],"struct":[["OneTime","Encapsulation of a RwLock<Option> for one-time initialization. This implementation will purposefully fail hard if not used properly, for example if not initialized before being first used (borrowed)."],["RateCounter","A rate counter tracks the number of transfers, the amount of data exchanged and the rate of transfer (via a few timers) over the last minute. The counter does not try to be accurate and update times proactively, instead it only does so lazily. As a result, produced rates are worst-case estimates."],["StopState","Global stopped/paused state shared across various subcomponents of Epic."]],"type":[["Mutex","A mutual exclusion primitive useful for protecting shared data"],["RwLock","A reader-writer lock"],["RwLockReadGuard","RAII structure used to release the shared read access of a lock when dropped."]]});