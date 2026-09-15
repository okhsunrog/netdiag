package dev.okhsunrog.netdiag.ipc

import android.content.Context
import android.os.Process
import android.util.Log
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

private const val TAG = "DaemonLauncher"

/**
 * Starts the privileged daemon through `su`.
 *
 * The daemon binary rides in the APK as `libnetdiagd.so`. That name is not
 * cosmetic: the package installer extracts files from `lib/<abi>/` to a
 * directory that permits execution and marks them executable, and it only does
 * that for files matching `lib*.so`. Shipping the same binary as an asset
 * would land it somewhere with noexec, and copying it out at runtime is what
 * W^X restrictions on newer Android releases are designed to stop.
 */
class DaemonLauncher(private val context: Context) {

    sealed interface Result {
        data object AlreadyRunning : Result
        data class Started(val output: String) : Result
        data class NoRoot(val detail: String) : Result
        data class Failed(val detail: String) : Result
    }

    private val binaryPath: String
        get() = File(context.applicationInfo.nativeLibraryDir, "libnetdiagd.so").absolutePath

    /** Is the daemon binary actually present in this build? */
    fun isBinaryBundled(): Boolean = File(binaryPath).exists()

    /**
     * Ask `su` whether root is available at all, without starting anything.
     * Kept separate so the UI can tell "no root" apart from "root, but the
     * daemon would not start".
     */
    suspend fun hasRoot(): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val process = ProcessBuilder("su", "-c", "id -u")
                .redirectErrorStream(true)
                .start()
            val output = withTimeout(ROOT_CHECK_TIMEOUT_MS) {
                process.inputStream.bufferedReader().readText().trim()
            }
            process.waitFor()
            output.lineSequence().any { it.trim() == "0" }
        }.getOrElse { false }
    }

    /**
     * Start the daemon if it is not already listening.
     *
     * The uid allowlist is the daemon's actual access control, so it is passed
     * here rather than assumed: the daemon checks SO_PEERCRED against it and
     * refuses anyone else, including other apps on the same device.
     */
    suspend fun ensureRunning(
        socketName: String = DaemonClient.DEFAULT_SOCKET_NAME,
    ): Result = withContext(Dispatchers.IO) {
        if (!isBinaryBundled()) {
            return@withContext Result.Failed(
                "the daemon binary is not bundled in this build; run scripts/build-daemon.sh",
            )
        }
        if (isListening(socketName)) {
            return@withContext Result.AlreadyRunning
        }
        if (!hasRoot()) {
            return@withContext Result.NoRoot(
                "su is unavailable or denied this app root access",
            )
        }

        val uid = Process.myUid()
        val command = buildString {
            append("nohup ")
            append(shellQuote(binaryPath))
            append(" --socket @").append(socketName)
            append(" --allow-uid ").append(uid)
            append(" --expect-package ").append(shellQuote(context.packageName))
            // Detach so the daemon outlives the su shell we started it from.
            append(" >/dev/null 2>&1 &")
        }

        Log.i(TAG, "starting the daemon: $command")

        return@withContext try {
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            // The daemon takes a moment to bind; poll rather than sleeping a
            // fixed amount, so a fast device is not made to wait.
            val bound = withTimeout(START_TIMEOUT_MS) {
                var listening = false
                while (!listening) {
                    if (isListening(socketName)) {
                        listening = true
                    } else {
                        delay(POLL_INTERVAL_MS)
                    }
                }
                listening
            }

            if (bound) {
                Result.Started(output.trim())
            } else {
                Result.Failed("the daemon did not bind @$socketName")
            }
        } catch (e: TimeoutCancellationException) {
            Result.Failed(
                "the daemon did not start listening within ${START_TIMEOUT_MS}ms; check " +
                    "logcat for its output",
            )
        } catch (e: Exception) {
            Result.Failed(e.message ?: e.toString())
        }
    }

    /** Ask the daemon to exit. */
    suspend fun stop(): Boolean = withContext(Dispatchers.IO) {
        runCatching {
            val process = ProcessBuilder("su", "-c", "pkill -f libnetdiagd.so")
                .redirectErrorStream(true)
                .start()
            process.waitFor()
            true
        }.getOrElse { false }
    }

    /**
     * Probe the abstract socket by connecting to it. Cheaper and more reliable
     * than parsing `ps` output, and it tests the thing we actually care about.
     */
    private fun isListening(socketName: String): Boolean = runCatching {
        android.net.LocalSocket(android.net.LocalSocket.SOCKET_STREAM).use { socket ->
            socket.connect(
                android.net.LocalSocketAddress(
                    socketName,
                    android.net.LocalSocketAddress.Namespace.ABSTRACT,
                ),
            )
            true
        }
    }.getOrElse { false }

    /** Single-quote for the shell, escaping any embedded quote. */
    private fun shellQuote(value: String): String =
        "'" + value.replace("'", "'\\''") + "'"

    private companion object {
        const val ROOT_CHECK_TIMEOUT_MS = 10_000L
        const val START_TIMEOUT_MS = 8_000L
        const val POLL_INTERVAL_MS = 150L
    }
}
