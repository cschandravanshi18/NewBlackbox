package top.niunaijun.blackboxa.view.setting

import android.content.Context
import android.os.Bundle
import android.widget.EditText
import android.widget.LinearLayout
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.afollestad.materialdialogs.MaterialDialog
import com.afollestad.materialdialogs.customview.customView
import top.niunaijun.blackbox.BlackBoxCore
import top.niunaijun.blackboxa.R
import top.niunaijun.blackboxa.app.AppManager
import top.niunaijun.blackboxa.util.toast
import top.niunaijun.blackboxa.view.gms.GmsManagerActivity
import java.io.File

class SettingFragment : PreferenceFragmentCompat() {

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.setting, rootKey)

        initCustomUuid()
        initGms()

        invalidHideState {
            val rootHidePreference: Preference = (findPreference("root_hide")!!)
            val hideRoot = AppManager.mBlackBoxLoader.hideRoot()
            rootHidePreference.setDefaultValue(hideRoot)
            rootHidePreference
        }

        invalidHideState {
            val daemonPreference: Preference = (findPreference("daemon_enable")!!)
            val mDaemonEnable = AppManager.mBlackBoxLoader.daemonEnable()
            daemonPreference.setDefaultValue(mDaemonEnable)
            daemonPreference
        }

        invalidHideState {
            val vpnPreference: Preference = (findPreference("use_vpn_network")!!)
            val mUseVpnNetwork = AppManager.mBlackBoxLoader.useVpnNetwork()
            vpnPreference.setDefaultValue(mUseVpnNetwork)
            vpnPreference
        }

        invalidHideState {
            val disableFlagSecurePreference: Preference = (findPreference("disable_flag_secure")!!)
            val mDisableFlagSecure = AppManager.mBlackBoxLoader.disableFlagSecure()
            disableFlagSecurePreference.setDefaultValue(mDisableFlagSecure)
            disableFlagSecurePreference
        }

        initSendLogs()
    }

    private fun getUuidFile(context: Context): File {
        return File(context.filesDir, "custom_device_uuid.txt")
    }

    private fun readSavedUuid(context: Context): String {
        return try {
            val file = getUuidFile(context)
            if (file.exists()) file.readText().trim() else ""
        } catch (e: Exception) {
            ""
        }
    }

    private fun saveCustomUuid(context: Context, uuid: String) {
        try {
            val file = getUuidFile(context)
            if (uuid.isEmpty()) {
                if (file.exists()) file.delete()
            } else {
                file.writeText(uuid.trim())
                file.setReadable(true, false)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun initCustomUuid() {
        val ctx = requireContext()
        val currentUuid = readSavedUuid(ctx)

        val uuidPref = Preference(ctx).apply {
            key = "custom_device_uuid"
            title = "Custom Device UUID"
            summary = if (currentUuid.isNotEmpty()) currentUuid else "Not set (Using random UUID)"
            order = -1
            setOnPreferenceClickListener {
                showUuidInputDialog(this)
                true
            }
        }
        preferenceScreen.addPreference(uuidPref)
    }

    private fun showUuidInputDialog(pref: Preference) {
        val ctx = requireContext()
        val container = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (20 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding / 2, padding, 0)
        }

        val uuidInput = EditText(ctx).apply {
            hint = "e.g. 43a1c5b4-1301-4a28-826c-5822d5328b38"
            setText(readSavedUuid(ctx))
            setSingleLine(true)
        }
        container.addView(uuidInput)

        MaterialDialog(ctx).show {
            title(text = "Set Fixed Device UUID")
            customView(view = container, scrollable = true)
            neutralButton(text = "Clear") {
                saveCustomUuid(ctx, "")
                pref.summary = "Not set (Using random UUID)"
                toast("Custom UUID cleared")
            }
            negativeButton(R.string.cancel)
            positiveButton(R.string.done) {
                val entered = uuidInput.text.toString().trim()
                saveCustomUuid(ctx, entered)
                pref.summary = if (entered.isNotEmpty()) entered else "Not set (Using random UUID)"
                toast("Device UUID saved! Restart cloned app.")
            }
        }
    }

    private fun initGms() {
        val gmsManagerPreference: Preference = (findPreference("gms_manager")!!)

        if (BlackBoxCore.get().isSupportGms) {
            gmsManagerPreference.setOnPreferenceClickListener {
                GmsManagerActivity.start(requireContext())
                true
            }
        } else {
            gmsManagerPreference.summary = getString(R.string.no_gms)
            gmsManagerPreference.isEnabled = false
        }
    }

    private fun invalidHideState(block: () -> Preference) {
        val pref = block()
        pref.setOnPreferenceChangeListener { preference, newValue ->
            val tmpHide = (newValue == true)
            when (preference.key) {
                "root_hide" -> AppManager.mBlackBoxLoader.invalidHideRoot(tmpHide)
                "daemon_enable" -> AppManager.mBlackBoxLoader.invalidDaemonEnable(tmpHide)
                "use_vpn_network" -> AppManager.mBlackBoxLoader.invalidUseVpnNetwork(tmpHide)
                "disable_flag_secure" -> AppManager.mBlackBoxLoader.invalidDisableFlagSecure(tmpHide)
            }
            toast(R.string.restart_module)
            return@setOnPreferenceChangeListener true
        }
    }

    private fun initSendLogs() {
        val sendLogsPreference: Preference? = findPreference("send_logs")
        sendLogsPreference?.setOnPreferenceClickListener {
            it.isEnabled = false
            BlackBoxCore.get()
                .sendLogs(
                    "Manual Log Upload from Settings",
                    true,
                    object : BlackBoxCore.LogSendListener {
                        override fun onSuccess() {
                            activity?.runOnUiThread { sendLogsPreference.isEnabled = true }
                        }

                        override fun onFailure(error: String?) {
                            activity?.runOnUiThread { sendLogsPreference.isEnabled = true }
                        }
                    }
                )
            toast("Sending logs... (Check notifications for status)")
            true
        }
    }
}
