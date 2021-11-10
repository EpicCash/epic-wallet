initSidebarItems({"enum":[["ErrorKind","A list specifying general categories of I/O error."]],"fn":[["copy","Creates a future which represents copying all the bytes from one object to another."],["flush","Creates a future which will entirely flush an I/O object and then yield the object itself."],["lines","Creates a new stream from the I/O object given representing the lines of input that are found on `A`."],["read_exact","Creates a future which will read exactly enough bytes to fill `buf`, returning an error if EOF is hit sooner."],["read_to_end","Creates a future which will read all the bytes associated with the I/O object `A` into the buffer provided."],["read_until","Creates a future which will read all the bytes associated with the I/O object `A` into the buffer provided until the delimiter `byte` is reached. This method is the async equivalent to `BufRead::read_until`."],["shutdown","Creates a future which will entirely shutdown an I/O object and then yield the object itself."],["stderr","Constructs a new handle to the standard error of the current process."],["stdin","Constructs a new handle to the standard input of the current process."],["stdout","Constructs a new handle to the standard output of the current process."],["write_all","Creates a future that will write the entire contents of the buffer `buf` to the stream `a` provided."]],"struct":[["Copy","A future which will copy all data from a reader into a writer."],["Error","The error type for I/O operations of the `Read`, `Write`, `Seek`, and associated traits."],["Flush","A future used to fully flush an I/O object."],["Lines","Combinator created by the top-level `lines` method which is a stream over the lines of text on an I/O object."],["ReadExact","A future which can be used to easily read exactly enough bytes to fill a buffer."],["ReadHalf","The readable half of an object returned from `AsyncRead::split`."],["ReadToEnd","A future which can be used to easily read the entire contents of a stream into a vector."],["ReadUntil","A future which can be used to easily read the contents of a stream into a vector until the delimiter is reached."],["Shutdown","A future used to fully shutdown an I/O object."],["Stderr","A handle to the standard error stream of a process."],["Stdin","A handle to the standard input stream of a process."],["Stdout","A handle to the standard output stream of a process."],["WriteAll","A future used to write the entire contents of some data to a stream."],["WriteHalf","The writable half of an object returned from `AsyncRead::split`."]],"trait":[["AsyncRead","Read bytes asynchronously."],["AsyncWrite","Writes bytes asynchronously."],["Read","The `Read` trait allows for reading bytes from a source."],["Write","A trait for objects which are byte-oriented sinks."]],"type":[["Result","A specialized `Result` type for I/O operations."]]});