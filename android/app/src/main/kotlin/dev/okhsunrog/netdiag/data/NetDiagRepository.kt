package dev.okhsunrog.netdiag.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log
import dev.okhsunrog.netdiag.framework.FrameworkCollector
import dev.okhsunrog.netdiag.framework.NetworkEventSource
import dev.okhsunrog.netdiag.ipc.ConnectionState
import dev.okhsunrog.netdiag.ipc.DaemonClient
import dev.okhsunrog.netdiag.ipc.DaemonLauncher
import dev.okhsunrog.netdiag.proto.AndroidNetworkState
import dev.okhsunrog.netdiag.proto.AppNetworkState
import dev.okhsunrog.netdiag.proto.AppRef
import dev.okhsunrog.netdiag.proto.CapturedPacket
import dev.okhsunrog.netdiag.proto.Check
import dev.okhsunrog.netdiag.proto.DiagnoseResponse
import dev.okhsunrog.netdiag.proto.HelloResponse
import dev.okhsunrog.netdiag.proto.NetworkEvent
import dev.okhsunrog.netdiag.proto.RouteLookup
import dev.okhsunrog.netdiag.proto.ServerFrame
import dev.okhsunrog.netdiag.proto.Snapshot
import dev.okhsunrog.netdiag.proto.SocketFilter
import dev.okhsunrog.netdiag.proto.StartCaptureRequest
import dev.okhsunrog.netdiag.proto.appRef
import dev.okhsunrog.netdiag.proto.clientFrame
import dev.okhsunrog.netdiag.proto.diagnoseRequest
import dev.okhsunrog.netdiag.proto.diagnoseTarget
import dev.okhsunrog.netdiag.proto.getAppNetworkStateRequest
import dev.okhsunrog.netdiag.proto.getSnapshotRequest
import dev.okhsunrog.netdiag.proto.getSocketsRequest
import dev.okhsunrog.netdiag.proto.pushFrameworkEventRequest
import dev.okhsunrog.netdiag.proto.routeLookupRequest
import dev.okhsunrog.netdiag.proto.watchNetworkRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "NetDiagRepository"

/** An installed app, as shown in the per-app view. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val uid: Int,
    val isSystem: Boolean,
)

/**
 * Single entry point for everything the UI needs.
 *
 * Its job is to keep the two halves of the picture together: every daemon call
 * that can benefit from the framework's view gets it attached automatically,
 * because the correlation checks in the daemon are skipped without it and a
 * screen that forgot to pass it would silently lose half the analysis.
 */
class NetDiagRepository(
    private val context: Context,
    private val client: DaemonClient = DaemonClient(),
) {
    private val launcher = DaemonLauncher(context)
    private val collector = FrameworkCollector(context)
    private val eventSource = NetworkEventSource(context, collector)
    private val packageManager: PackageManager = context.packageManager

    val connectionState: StateFlow<ConnectionState> = client.state

    suspend fun hasRoot(): Boolean = launcher.hasRoot()

    fun isDaemonBundled(): Boolean = launcher.isBinaryBundled()

    /** Start the daemon if needed, then connect and handshake. */
    suspend fun connect(scope: CoroutineScope): Result<HelloResponse> = runCatching {
        when (val result = launcher.ensureRunning()) {
            is DaemonLauncher.Result.NoRoot ->
                error("root is required: ${result.detail}")
            is DaemonLauncher.Result.Failed ->
                error("could not start the daemon: ${result.detail}")
            else -> Unit
        }
        val version = runCatching {
            packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull().orEmpty()
        client.connect(scope, version)
    }

    fun disconnect() = client.disconnect()

    suspend fun stopDaemon(): Boolean {
        client.disconnect()
        return launcher.stop()
    }

    /** The framework's current view, captured fresh. */
    fun frameworkState(): AndroidNetworkState = collector.collect()

    // ---- Collection -------------------------------------------------------

    suspend fun snapshot(
        includeSockets: Boolean = true,
        includeFirewall: Boolean = true,
    ): Snapshot = withContext(Dispatchers.IO) {
        val frame = client.unary(
            clientFrame {
                getSnapshot = getSnapshotRequest {
                    this.includeSockets = includeSockets
                    includeSocketTcpInfo = includeSockets
                    includeNeighbors = true
                    this.includeFirewall = includeFirewall
                    includeQdiscs = true
                    includeCounters = true
                    includeSysctls = true
                    // Bundle the framework view so the snapshot is a complete,
                    // self-contained record of both layers at one instant.
                    androidState = frameworkState()
                }
            },
        )
        frame.getSnapshot.snapshot
    }

    suspend fun sockets(filter: SocketFilter): dev.okhsunrog.netdiag.proto.GetSocketsResponse =
        withContext(Dispatchers.IO) {
            client.unary(
                clientFrame { getSockets = getSocketsRequest { this.filter = filter } },
            ).getSockets
        }

    suspend fun routeLookup(
        destination: dev.okhsunrog.netdiag.proto.IpAddress,
        uid: Int? = null,
    ): RouteLookup = withContext(Dispatchers.IO) {
        client.unary(
            clientFrame {
                routeLookup = routeLookupRequest {
                    this.destination = destination
                    uid?.let {
                        this.uid = it
                        hasUid = true
                    }
                }
            },
        ).routeLookup.lookup
    }

    // ---- Correlation ------------------------------------------------------

    suspend fun appNetworkState(app: InstalledApp): AppNetworkState =
        withContext(Dispatchers.IO) {
            client.unary(
                clientFrame {
                    getAppNetworkState = getAppNetworkStateRequest {
                        this.app = appRef {
                            packageName = app.packageName
                            uid = app.uid
                            label = app.label
                            isSystem = app.isSystem
                        }
                        androidState = frameworkState()
                        includeTcpInfo = true
                    }
                },
            ).getAppNetworkState.state
        }

    /**
     * Installed apps that could plausibly use the network, most recently
     * updated first.
     */
    suspend fun installedApps(includeSystem: Boolean = false): List<InstalledApp> =
        withContext(Dispatchers.IO) {
            val flags = PackageManager.GET_META_DATA
            packageManager.getInstalledApplications(flags)
                .asSequence()
                .filter { info ->
                    val system = info.flags and ApplicationInfo.FLAG_SYSTEM != 0
                    includeSystem || !system
                }
                .map { info ->
                    InstalledApp(
                        packageName = info.packageName,
                        label = runCatching {
                            packageManager.getApplicationLabel(info).toString()
                        }.getOrDefault(info.packageName),
                        uid = info.uid,
                        isSystem = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                    )
                }
                .sortedBy { it.label.lowercase() }
                .toList()
        }

    /** Resolve the package names sharing a uid, for socket attribution. */
    fun packagesForUid(uid: Int): List<String> =
        runCatching { packageManager.getPackagesForUid(uid)?.toList() }
            .getOrNull()
            .orEmpty()

    // ---- Diagnosis --------------------------------------------------------

    sealed interface DiagnoseProgress {
        data class CheckCompleted(val check: Check) : DiagnoseProgress
        data class Finished(val response: DiagnoseResponse) : DiagnoseProgress
    }

    /**
     * Run the diagnosis, streaming each check as it completes so the UI fills
     * in progressively instead of showing a spinner for several seconds.
     */
    fun diagnose(
        hostname: String = "",
        netId: Int = 0,
        uid: Int? = null,
        passiveOnly: Boolean = false,
    ): Flow<DiagnoseProgress> = client.stream(
        clientFrame {
            diagnose = diagnoseRequest {
                this.passiveOnly = passiveOnly
                androidState = frameworkState()
                target = diagnoseTarget {
                    if (hostname.isNotBlank()) this.hostname = hostname
                    if (netId != 0) this.netId = netId
                    uid?.let {
                        asUid = it
                        hasAsUid = true
                    }
                }
            }
        },
    ).map { frame ->
        val progress = frame.diagnose
        if (progress.hasResponse()) {
            DiagnoseProgress.Finished(progress.response)
        } else {
            DiagnoseProgress.CheckCompleted(progress.check)
        }
    }

    // ---- Timeline ---------------------------------------------------------

    /**
     * The merged timeline: kernel events from the daemon and framework events
     * from ConnectivityManager, on one axis.
     *
     * Framework events are also pushed back to the daemon, so its own view of
     * the timeline stays complete for anything that reads it later.
     */
    fun timeline(scope: CoroutineScope, replayInitialState: Boolean = true): Flow<NetworkEvent> {
        val kernel = client.stream(
            clientFrame {
                watchNetwork = watchNetworkRequest {
                    this.replayInitialState = replayInitialState
                }
            },
        ).map { frame: ServerFrame -> frame.event }

        val framework = eventSource.events()
            .map { event ->
                // Best-effort: a failure to forward must not break the UI's
                // own timeline.
                scope.launch {
                    runCatching {
                        client.unary(
                            clientFrame {
                                pushFrameworkEvent = pushFrameworkEventRequest {
                                    events += event
                                }
                            },
                        )
                    }.onFailure { Log.d(TAG, "could not forward an event: ${it.message}") }
                }
                event
            }

        return merge(kernel, framework)
    }

    // ---- Capture ----------------------------------------------------------

    sealed interface CaptureEvent {
        data class Started(
            val captureId: Long,
            val interfaceName: String,
            val pcapFileHeader: ByteArray,
        ) : CaptureEvent {
            override fun equals(other: Any?): Boolean =
                this === other ||
                    (other is Started && captureId == other.captureId)

            override fun hashCode(): Int = captureId.hashCode()
        }

        data class Packet(val packet: CapturedPacket) : CaptureEvent
        data class Finished(val reason: String, val packets: Long) : CaptureEvent
    }

    fun capture(request: StartCaptureRequest): Flow<CaptureEvent> = flow {
        client.stream(clientFrame { startCapture = request }).collect { frame ->
            when {
                frame.hasCaptureStarted() -> emit(
                    CaptureEvent.Started(
                        captureId = frame.captureStarted.captureId,
                        interfaceName = frame.captureStarted.interfaceName,
                        pcapFileHeader = frame.captureStarted.pcapFileHeader.toByteArray(),
                    ),
                )
                frame.hasPacket() -> emit(CaptureEvent.Packet(frame.packet))
                frame.hasCaptureFinished() -> emit(
                    CaptureEvent.Finished(
                        reason = frame.captureFinished.reason,
                        packets = frame.captureFinished.stats.packetsCaptured,
                    ),
                )
            }
        }
    }.catch { e ->
        Log.w(TAG, "capture ended: ${e.message}")
        emit(CaptureEvent.Finished(e.message ?: "error", 0))
    }
}
