package dev.okhsunrog.netdiag.ipc

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import dev.okhsunrog.netdiag.proto.ClientFrame
import dev.okhsunrog.netdiag.proto.ErrorCode
import dev.okhsunrog.netdiag.proto.HelloResponse
import dev.okhsunrog.netdiag.proto.ServerFrame
import dev.okhsunrog.netdiag.proto.cancelRequest
import dev.okhsunrog.netdiag.proto.clientFrame
import dev.okhsunrog.netdiag.proto.helloRequest
import java.io.BufferedOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

private const val TAG = "DaemonClient"

/** Protocol version this build of the app speaks. Must match the daemon's. */
const val PROTOCOL_VERSION = 1

/**
 * Raised when the daemon answers a request with an [dev.okhsunrog.netdiag.proto.Error].
 * Carries the code so callers can distinguish "not supported on this device"
 * from "you asked for something that does not exist".
 */
class DaemonException(
    val code: ErrorCode,
    override val message: String,
    val detail: String = "",
) : Exception(message)

sealed interface ConnectionState {
    data object Disconnected : ConnectionState
    data object Connecting : ConnectionState
    data class Connected(val hello: HelloResponse) : ConnectionState
    data class Failed(val reason: String) : ConnectionState
}

/**
 * Client for the root daemon.
 *
 * One socket carries every call. Requests are tagged with a client-assigned
 * id and a single reader coroutine fans replies back out to whoever is waiting
 * on that id, so a three-second `Diagnose` and a live `WatchNetwork` can share
 * the connection without blocking each other.
 *
 * Framing is protobuf length-delimited, which `writeDelimitedTo` and
 * `parseDelimitedFrom` implement directly — the same encoding prost writes on
 * the daemon side, so neither end hand-rolls a header.
 */
class DaemonClient(
    private val socketName: String = DEFAULT_SOCKET_NAME,
) {
    companion object {
        const val DEFAULT_SOCKET_NAME = "netdiag"
    }

    private var socket: LocalSocket? = null
    private var output: BufferedOutputStream? = null
    private var readerJob: Job? = null
    private var scope: CoroutineScope? = null

    private val nextId = AtomicLong(1)
    private val writeLock = Mutex()

    /** In-flight calls, keyed by request id. */
    private val pending = ConcurrentHashMap<Long, Channel<ServerFrame>>()

    private val _state = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    val isConnected: Boolean
        get() = _state.value is ConnectionState.Connected

    /**
     * Connect and complete the handshake. The daemon refuses every other
     * request until Hello has been exchanged, so this is not optional.
     */
    suspend fun connect(
        parentScope: CoroutineScope,
        clientVersion: String,
    ): HelloResponse = withContext(Dispatchers.IO) {
        disconnect()
        _state.value = ConnectionState.Connecting

        try {
            val local = LocalSocket(LocalSocket.SOCKET_STREAM)
            // The abstract namespace has no filesystem entry to mislabel under
            // SELinux, and no stale socket file to clean up if either side is
            // killed. The daemon authorizes us from SO_PEERCRED instead.
            local.connect(
                LocalSocketAddress(socketName, LocalSocketAddress.Namespace.ABSTRACT),
            )
            socket = local
            output = BufferedOutputStream(local.outputStream)

            val readerScope = CoroutineScope(parentScope.coroutineContext + Dispatchers.IO)
            scope = readerScope
            readerJob = readerScope.launch { readLoop(local.inputStream) }

            val response = unary(
                clientFrame {
                    hello = helloRequest {
                        protocolVersion = PROTOCOL_VERSION
                        clientName = "netdiag-android"
                        this.clientVersion = clientVersion
                    }
                },
            ).hello

            if (response.protocolVersion != PROTOCOL_VERSION) {
                Log.w(
                    TAG,
                    "daemon speaks protocol ${response.protocolVersion}, app speaks " +
                        "$PROTOCOL_VERSION; continuing on the negotiated version",
                )
            }

            _state.value = ConnectionState.Connected(response)
            response
        } catch (e: Exception) {
            disconnect()
            _state.value = ConnectionState.Failed(e.message ?: e.toString())
            throw e
        }
    }

    fun disconnect() {
        readerJob?.cancel()
        readerJob = null
        scope = null
        // Fail every waiter rather than letting them hang forever.
        pending.values.forEach { it.close(IOException("the connection was closed")) }
        pending.clear()
        runCatching { output?.flush() }
        runCatching { socket?.close() }
        socket = null
        output = null
        if (_state.value is ConnectionState.Connected) {
            _state.value = ConnectionState.Disconnected
        }
    }

    /**
     * Send a request and wait for its single reply.
     */
    suspend fun unary(build: ClientFrame): ServerFrame = withContext(Dispatchers.IO) {
        val id = nextId.getAndIncrement()
        val channel = Channel<ServerFrame>(Channel.BUFFERED)
        pending[id] = channel
        try {
            send(build.toBuilder().setId(id).build())
            val frame = channel.receive()
            frame.throwIfError()
            frame
        } finally {
            pending.remove(id)
            channel.close()
        }
    }

    /**
     * Send a streaming request and emit every frame until the daemon sends
     * `stream_end`.
     *
     * Cancelling collection sends an explicit Cancel, because the daemon has
     * no other way to know: the socket stays open for other calls, so simply
     * walking away would leave a capture running as root.
     */
    fun stream(build: ClientFrame): Flow<ServerFrame> = flow {
        val id = nextId.getAndIncrement()
        val channel = Channel<ServerFrame>(Channel.BUFFERED)
        pending[id] = channel
        var completed = false
        try {
            send(build.toBuilder().setId(id).build())
            while (true) {
                val frame = channel.receive()
                if (frame.hasStreamEnd()) {
                    completed = true
                    val end = frame.streamEnd
                    if (end.hasError()) {
                        throw DaemonException(
                            end.error.code,
                            end.error.message,
                            end.error.detail,
                        )
                    }
                    break
                }
                frame.throwIfError()
                emit(frame)
            }
        } finally {
            pending.remove(id)
            channel.close()
            if (!completed && isConnected) {
                runCatching { cancelCall(id) }
            }
        }
    }

    /** Tell the daemon to stop a stream we are no longer collecting. */
    private suspend fun cancelCall(targetId: Long) {
        val id = nextId.getAndIncrement()
        send(
            clientFrame {
                this.id = id
                cancel = cancelRequest { this.targetId = targetId }
            },
        )
    }

    private suspend fun send(frame: ClientFrame) {
        writeLock.withLock {
            val stream = output ?: throw IOException("not connected to the daemon")
            withContext(Dispatchers.IO) {
                frame.writeDelimitedTo(stream)
                stream.flush()
            }
        }
    }

    private suspend fun readLoop(input: InputStream) {
        try {
            while (scope?.isActive == true) {
                val frame = ServerFrame.parseDelimitedFrom(input) ?: break
                val channel = pending[frame.id]
                if (channel == null) {
                    // A late frame for a call we already abandoned. Expected
                    // between cancelling a stream and its stream_end arriving.
                    Log.d(TAG, "dropping a frame for unknown request ${frame.id}")
                    continue
                }
                channel.trySend(frame)
            }
        } catch (e: Exception) {
            Log.w(TAG, "the daemon connection dropped: ${e.message}")
        } finally {
            pending.values.forEach { it.close(IOException("the daemon connection dropped")) }
            pending.clear()
            _state.value = ConnectionState.Disconnected
        }
    }
}

private fun ServerFrame.throwIfError() {
    if (hasError()) {
        throw DaemonException(error.code, error.message, error.detail)
    }
}
