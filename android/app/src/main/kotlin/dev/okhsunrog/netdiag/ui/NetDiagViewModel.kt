package dev.okhsunrog.netdiag.ui

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.okhsunrog.netdiag.data.InstalledApp
import dev.okhsunrog.netdiag.data.NetDiagRepository
import dev.okhsunrog.netdiag.ipc.ConnectionState
import dev.okhsunrog.netdiag.proto.AndroidNetworkState
import dev.okhsunrog.netdiag.proto.AppNetworkState
import dev.okhsunrog.netdiag.proto.CapturedPacket
import dev.okhsunrog.netdiag.proto.Check
import dev.okhsunrog.netdiag.proto.CheckStatus
import dev.okhsunrog.netdiag.proto.DiagnoseResponse
import dev.okhsunrog.netdiag.proto.NetworkEvent
import dev.okhsunrog.netdiag.proto.Snapshot
import dev.okhsunrog.netdiag.proto.startCaptureRequest
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "NetDiagViewModel"

/** Events kept in memory for the timeline. Older ones are dropped. */
private const val TIMELINE_CAPACITY = 2000

data class SnapshotState(
    val snapshot: Snapshot? = null,
    val framework: AndroidNetworkState? = null,
    val loading: Boolean = false,
    val error: String? = null,
)

data class DiagnosisState(
    val checks: List<Check> = emptyList(),
    val response: DiagnoseResponse? = null,
    val running: Boolean = false,
    val error: String? = null,
)

data class AppsState(
    val apps: List<InstalledApp> = emptyList(),
    val selected: AppNetworkState? = null,
    val loading: Boolean = false,
    val includeSystem: Boolean = false,
    val error: String? = null,
)

data class TimelineState(
    val events: List<NetworkEvent> = emptyList(),
    val running: Boolean = false,
    val error: String? = null,
)

data class CaptureState(
    val packets: List<CapturedPacket> = emptyList(),
    val interfaceName: String = "",
    val running: Boolean = false,
    val bytes: Long = 0,
    /** The pcap file header the daemon sent, kept so a save writes a valid file. */
    val pcapHeader: ByteArray = ByteArray(0),
    val savedPath: String? = null,
    val error: String? = null,
) {
    override fun equals(other: Any?): Boolean =
        this === other ||
            (
                other is CaptureState &&
                    packets == other.packets &&
                    interfaceName == other.interfaceName &&
                    running == other.running &&
                    bytes == other.bytes &&
                    savedPath == other.savedPath &&
                    error == other.error
                )

    override fun hashCode(): Int {
        var result = packets.hashCode()
        result = 31 * result + interfaceName.hashCode()
        result = 31 * result + running.hashCode()
        result = 31 * result + bytes.hashCode()
        result = 31 * result + (savedPath?.hashCode() ?: 0)
        result = 31 * result + (error?.hashCode() ?: 0)
        return result
    }
}

class NetDiagViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = NetDiagRepository(application)

    val connectionState: StateFlow<ConnectionState> = repository.connectionState
        .stateIn(viewModelScope, SharingStarted.Eagerly, ConnectionState.Disconnected)

    private val _snapshot = MutableStateFlow(SnapshotState())
    val snapshot: StateFlow<SnapshotState> = _snapshot.asStateFlow()

    private val _diagnosis = MutableStateFlow(DiagnosisState())
    val diagnosis: StateFlow<DiagnosisState> = _diagnosis.asStateFlow()

    private val _apps = MutableStateFlow(AppsState())
    val apps: StateFlow<AppsState> = _apps.asStateFlow()

    private val _timeline = MutableStateFlow(TimelineState())
    val timeline: StateFlow<TimelineState> = _timeline.asStateFlow()

    private val _capture = MutableStateFlow(CaptureState())
    val capture: StateFlow<CaptureState> = _capture.asStateFlow()

    private val _connectError = MutableStateFlow<String?>(null)
    val connectError: StateFlow<String?> = _connectError.asStateFlow()

    private var diagnoseJob: Job? = null
    private var timelineJob: Job? = null
    private var captureJob: Job? = null

    val isDaemonBundled: Boolean get() = repository.isDaemonBundled()

    fun connect() {
        viewModelScope.launch {
            _connectError.value = null
            repository.connect(viewModelScope)
                .onSuccess {
                    // The overview is what the user sees first, so load it
                    // immediately rather than waiting for them to pull.
                    refreshSnapshot()
                    startTimeline()
                }
                .onFailure { e ->
                    Log.w(TAG, "connect failed", e)
                    _connectError.value = e.message ?: e.toString()
                }
        }
    }

    fun disconnect() {
        timelineJob?.cancel()
        diagnoseJob?.cancel()
        captureJob?.cancel()
        repository.disconnect()
        _timeline.value = TimelineState()
    }

    fun stopDaemon() {
        viewModelScope.launch {
            timelineJob?.cancel()
            repository.stopDaemon()
        }
    }

    // ---- Overview ---------------------------------------------------------

    fun refreshSnapshot() {
        viewModelScope.launch {
            _snapshot.value = _snapshot.value.copy(loading = true, error = null)
            runCatching { repository.snapshot() }
                .onSuccess { snapshot ->
                    _snapshot.value = SnapshotState(
                        snapshot = snapshot,
                        framework = snapshot.androidState,
                        loading = false,
                    )
                }
                .onFailure { e ->
                    _snapshot.value = _snapshot.value.copy(
                        loading = false,
                        error = e.message ?: e.toString(),
                    )
                }
        }
    }

    // ---- Diagnosis --------------------------------------------------------

    fun diagnose(hostname: String = "", uid: Int? = null) {
        diagnoseJob?.cancel()
        _diagnosis.value = DiagnosisState(running = true)
        diagnoseJob = viewModelScope.launch {
            runCatching {
                repository.diagnose(hostname = hostname, uid = uid).collect { progress ->
                    when (progress) {
                        is NetDiagRepository.DiagnoseProgress.CheckCompleted -> {
                            // Replace rather than append: a check can be
                            // streamed once and then restated in the final
                            // response, and duplicating rows would be
                            // confusing mid-run.
                            val existing = _diagnosis.value.checks
                            val merged = existing.filterNot { it.key == progress.check.key } +
                                progress.check
                            _diagnosis.value = _diagnosis.value.copy(checks = merged)
                        }
                        is NetDiagRepository.DiagnoseProgress.Finished -> {
                            _diagnosis.value = DiagnosisState(
                                checks = progress.response.checksList,
                                response = progress.response,
                                running = false,
                            )
                        }
                    }
                }
            }.onFailure { e ->
                _diagnosis.value = _diagnosis.value.copy(
                    running = false,
                    error = e.message ?: e.toString(),
                )
            }
            if (_diagnosis.value.running) {
                _diagnosis.value = _diagnosis.value.copy(running = false)
            }
        }
    }

    fun cancelDiagnosis() {
        diagnoseJob?.cancel()
        _diagnosis.value = _diagnosis.value.copy(running = false)
    }

    // ---- Apps -------------------------------------------------------------

    fun loadApps(includeSystem: Boolean = _apps.value.includeSystem) {
        viewModelScope.launch {
            _apps.value = _apps.value.copy(loading = true, includeSystem = includeSystem)
            runCatching { repository.installedApps(includeSystem) }
                .onSuccess { list ->
                    _apps.value = _apps.value.copy(apps = list, loading = false)
                }
                .onFailure { e ->
                    _apps.value = _apps.value.copy(
                        loading = false,
                        error = e.message ?: e.toString(),
                    )
                }
        }
    }

    fun selectApp(app: InstalledApp) {
        viewModelScope.launch {
            _apps.value = _apps.value.copy(loading = true, error = null)
            runCatching { repository.appNetworkState(app) }
                .onSuccess { state ->
                    _apps.value = _apps.value.copy(selected = state, loading = false)
                }
                .onFailure { e ->
                    _apps.value = _apps.value.copy(
                        loading = false,
                        error = e.message ?: e.toString(),
                    )
                }
        }
    }

    fun clearSelectedApp() {
        _apps.value = _apps.value.copy(selected = null)
    }

    // ---- Timeline ---------------------------------------------------------

    fun startTimeline() {
        if (timelineJob?.isActive == true) return
        _timeline.value = _timeline.value.copy(running = true, error = null)
        timelineJob = viewModelScope.launch {
            runCatching {
                repository.timeline(viewModelScope).collect { event ->
                    val events = _timeline.value.events
                    // Newest first, bounded: an unbounded list would grow
                    // without limit on a device that is flapping.
                    val updated = (listOf(event) + events).take(TIMELINE_CAPACITY)
                    _timeline.value = _timeline.value.copy(events = updated)
                }
            }.onFailure { e ->
                _timeline.value = _timeline.value.copy(
                    running = false,
                    error = e.message ?: e.toString(),
                )
            }
        }
    }

    fun stopTimeline() {
        timelineJob?.cancel()
        timelineJob = null
        _timeline.value = _timeline.value.copy(running = false)
    }

    fun clearTimeline() {
        _timeline.value = _timeline.value.copy(events = emptyList())
    }

    // ---- Capture ----------------------------------------------------------

    /** Interfaces worth offering for capture: up, and not loopback. */
    fun captureInterfaces(): List<String> =
        _snapshot.value.snapshot
            ?.interfacesList
            ?.filter { it.hasFlags() && it.flags.up && !it.flags.loopback }
            ?.map { it.name }
            .orEmpty()

    fun selectCaptureInterface(name: String) {
        _capture.value = _capture.value.copy(interfaceName = name)
    }

    fun startCapture(interfaceName: String) {
        captureJob?.cancel()
        _capture.value = CaptureState(interfaceName = interfaceName, running = true)
        captureJob = viewModelScope.launch {
            val request = startCaptureRequest {
                this.interfaceName = interfaceName
                includePayload = true
                snaplen = CAPTURE_SNAPLEN
                maxPackets = CAPTURE_MAX_PACKETS
                durationMs = CAPTURE_DURATION_MS
            }
            runCatching {
                repository.capture(request).collect { event ->
                    when (event) {
                        is NetDiagRepository.CaptureEvent.Started -> {
                            _capture.value = _capture.value.copy(
                                pcapHeader = event.pcapFileHeader,
                                interfaceName = event.interfaceName,
                            )
                        }
                        is NetDiagRepository.CaptureEvent.Packet -> {
                            val current = _capture.value
                            _capture.value = current.copy(
                                packets = (current.packets + event.packet)
                                    .takeLast(CAPTURE_UI_LIMIT),
                                bytes = current.bytes + event.packet.originalLength,
                            )
                        }
                        is NetDiagRepository.CaptureEvent.Finished -> {
                            _capture.value = _capture.value.copy(running = false)
                        }
                    }
                }
            }.onFailure { e ->
                _capture.value = _capture.value.copy(
                    running = false,
                    error = e.message ?: e.toString(),
                )
            }
            _capture.value = _capture.value.copy(running = false)
        }
    }

    fun stopCapture() {
        captureJob?.cancel()
        captureJob = null
        _capture.value = _capture.value.copy(running = false)
    }

    /**
     * Write the captured packets as a pcap file the user can pull off the
     * device. The file header comes from the daemon, which is the only side
     * that knows the interface's real link type; guessing it here would
     * produce a file that every analyser misreads on cellular interfaces.
     */
    fun saveCapture() {
        viewModelScope.launch {
            val state = _capture.value
            if (state.packets.isEmpty() || state.pcapHeader.isEmpty()) {
                _capture.value = state.copy(error = "nothing to save")
                return@launch
            }
            runCatching {
                withContext(Dispatchers.IO) {
                    val directory = getApplication<Application>()
                        .getExternalFilesDir(null)
                        ?: getApplication<Application>().filesDir
                    val file = File(
                        directory,
                        "netdiag-${state.interfaceName}-${System.currentTimeMillis()}.pcap",
                    )
                    file.outputStream().buffered().use { out ->
                        out.write(state.pcapHeader)
                        state.packets.forEach { packet ->
                            val data = packet.data.toByteArray()
                            val record = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
                            record.putInt((packet.unixMs / 1000).toInt())
                            record.putInt(
                                ((packet.unixMs % 1000) * 1000 + packet.unixUsFraction).toInt(),
                            )
                            record.putInt(data.size)
                            record.putInt(packet.originalLength)
                            out.write(record.array())
                            out.write(data)
                        }
                    }
                    file.absolutePath
                }
            }.onSuccess { path ->
                _capture.value = _capture.value.copy(savedPath = path, error = null)
            }.onFailure { e ->
                _capture.value = _capture.value.copy(error = e.message ?: e.toString())
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        // Leave the daemon running: the user may want it up between app
        // launches, and stopping it is an explicit action in the UI.
        repository.disconnect()
    }

    private companion object {
        const val CAPTURE_SNAPLEN = 262_144
        const val CAPTURE_MAX_PACKETS = 5_000
        const val CAPTURE_DURATION_MS = 120_000
        /** Rows kept for display; the saved file is limited by the same cap. */
        const val CAPTURE_UI_LIMIT = 2_000
    }
}

/** Counts for the diagnosis summary bar. */
fun List<Check>.countByStatus(status: CheckStatus): Int = count { it.status == status }
