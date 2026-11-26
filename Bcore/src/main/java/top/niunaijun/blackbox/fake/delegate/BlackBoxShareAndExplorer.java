package top.niunaijun.blackbox.fake.delegate;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.media.MediaScannerConnection;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.WeakHashMap;

public final class BlackBoxShareAndExplorer {

    public static final String SHARE_FOLDER_NAME = "BlackBoxShare";
    private static final WeakHashMap<Activity, Boolean> ATTACHED = new WeakHashMap<>();

    private BlackBoxShareAndExplorer() {
    }

    public static File getMainDeviceShareDir() {
        File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        return new File(downloads, SHARE_FOLDER_NAME);
    }

    public static String copyFileToMainShare(Context context, File srcFile, String customName) {
        try {
            if (srcFile == null || !srcFile.exists() || !srcFile.canRead()) {
                return "ERR: File not readable";
            }
            File shareDir = getMainDeviceShareDir();
            if (!shareDir.exists() && !shareDir.mkdirs()) {
                return "ERR: Cannot create Download/" + SHARE_FOLDER_NAME;
            }
            String outName = (customName != null && !customName.trim().isEmpty())
                    ? customName.trim()
                    : srcFile.getName();
            File dstFile = new File(shareDir, outName);

            try (InputStream in = new FileInputStream(srcFile);
                 OutputStream out = new FileOutputStream(dstFile, false)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) != -1) {
                    out.write(buf, 0, len);
                }
                out.flush();
            }

            if (context != null) {
                MediaScannerConnection.scanFile(
                        context.getApplicationContext(),
                        new String[]{dstFile.getAbsolutePath()},
                        null,
                        null
                );
            }
            return "SHARED_OK: " + dstFile.getAbsolutePath() + " (" + dstFile.length() + "B)";
        } catch (Exception e) {
            return "ERR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static String replaceFileFromMainShare(Context context, File targetFile, File replacementFile) {
        try {
            if (targetFile == null) {
                return "ERR: Target file is null";
            }
            if (replacementFile == null || !replacementFile.exists() || !replacementFile.isFile() || !replacementFile.canRead()) {
                return "ERR: Replacement file not readable in BBShare";
            }
            if (targetFile.exists() && !targetFile.canWrite()) {
                return "ERR: Target not writable (w=false): " + targetFile.getAbsolutePath();
            }
            File parent = targetFile.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                return "ERR: Cannot create parent dir";
            }

            try (InputStream in = new FileInputStream(replacementFile);
                 OutputStream out = new FileOutputStream(targetFile, false)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) != -1) {
                    out.write(buf, 0, len);
                }
                out.flush();
            }

            if (context != null) {
                MediaScannerConnection.scanFile(
                        context.getApplicationContext(),
                        new String[]{targetFile.getAbsolutePath()},
                        null,
                        null
                );
            }
            return "REPLACED_OK: " + targetFile.getName() + " <- " + replacementFile.getName() + " (" + targetFile.length() + "B)";
        } catch (Exception e) {
            return "ERR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static String saveJsonDiagnosticToMainShare(Context context, String rawData, String prefix) {
        try {
            String trimmed = rawData == null ? "" : rawData.trim();
            String formattedJson;
            try {
                if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
                    formattedJson = new JSONObject(trimmed).toString(2);
                } else if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                    formattedJson = new JSONArray(trimmed).toString(2);
                } else {
                    JSONObject obj = new JSONObject();
                    obj.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).format(new Date()));
                    obj.put("raw", rawData == null ? "" : rawData);
                    formattedJson = obj.toString(2);
                }
            } catch (Exception ignored) {
                JSONObject obj = new JSONObject();
                obj.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).format(new Date()));
                obj.put("raw", rawData == null ? "" : rawData);
                formattedJson = obj.toString(2);
            }

            File shareDir = getMainDeviceShareDir();
            if (!shareDir.exists() && !shareDir.mkdirs()) {
                return "ERR: Cannot create Download/" + SHARE_FOLDER_NAME;
            }
            String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
            String safePrefix = (prefix == null || prefix.trim().isEmpty()) ? "diag" : prefix.trim();
            File dstFile = new File(shareDir, safePrefix + "_" + stamp + ".json");

            try (OutputStream out = new FileOutputStream(dstFile, false)) {
                out.write(formattedJson.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }

            if (context != null) {
                MediaScannerConnection.scanFile(
                        context.getApplicationContext(),
                        new String[]{dstFile.getAbsolutePath()},
                        new String[]{"application/json"},
                        null
                );
            }
            return "JSON_SAVED: " + dstFile.getAbsolutePath() + " (" + dstFile.length() + "B)";
        } catch (Exception e) {
            return "ERR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static void attachDefaultExplorer(final Activity activity) {
        if (activity == null || activity.isFinishing() || activity.isDestroyed()) {
            return;
        }
        synchronized (ATTACHED) {
            if (Boolean.TRUE.equals(ATTACHED.get(activity))) {
                return;
            }
            ATTACHED.put(activity, true);
        }

        new Handler(Looper.getMainLooper()).post(() -> {
            if (activity.isFinishing() || activity.isDestroyed()) {
                return;
            }
            ViewGroup root = activity.findViewById(android.R.id.content);
            if (!(root instanceof FrameLayout)) {
                return;
            }

            Button btn = new Button(activity);
            btn.setText("BB Share");
            btn.setTextSize(11f);
            btn.setTextColor(Color.WHITE);
            btn.setAllCaps(false);
            btn.setPadding(20, 10, 20, 10);

            GradientDrawable bg = new GradientDrawable();
            bg.setColor(0xCC1E293B);
            bg.setCornerRadius(24f);
            bg.setStroke(2, 0xFF38BDF8);
            btn.setBackground(bg);

            FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
            );
            params.gravity = Gravity.BOTTOM | Gravity.END;
            params.setMargins(16, 16, 16, 120);

            btn.setOnClickListener(v -> showRootChooser(activity));
            ((FrameLayout) root).addView(btn, params);
        });
    }

    private static void showRootChooser(final Activity activity) {
        File dataDir = activity.getApplicationInfo().dataDir != null
                ? new File(activity.getApplicationInfo().dataDir)
                : activity.getFilesDir().getParentFile();
        File filesDir = activity.getFilesDir();
        File cacheDir = activity.getCacheDir();
        File sharedPrefsDir = dataDir != null ? new File(dataDir, "shared_prefs") : null;
        File databasesDir = dataDir != null ? new File(dataDir, "databases") : null;
        File shareDir = getMainDeviceShareDir();

        final List<File> targets = new ArrayList<>();
        final List<String> labels = new ArrayList<>();

        addTargetIfPresent(targets, labels, "App Data Root", dataDir);
        addTargetIfPresent(targets, labels, "shared_prefs", sharedPrefsDir);
        addTargetIfPresent(targets, labels, "databases", databasesDir);
        addTargetIfPresent(targets, labels, "files", filesDir);
        addTargetIfPresent(targets, labels, "cache", cacheDir);
        addTargetIfPresent(targets, labels, "Download/" + SHARE_FOLDER_NAME, shareDir);

        new AlertDialog.Builder(activity)
                .setTitle("BlackBox Explorer")
                .setItems(labels.toArray(new String[0]), (dialog, which) -> showDirDialog(activity, targets.get(which)))
                .setNegativeButton("Close", null)
                .show();
    }

    private static void addTargetIfPresent(List<File> targets, List<String> labels, String title, File dir) {
        if (dir != null) {
            targets.add(dir);
            String perms = (dir.canRead() ? "r" : "-") + (dir.canWrite() ? "w" : "-");
            labels.add(title + " [" + perms + "] -> " + dir.getAbsolutePath());
        }
    }

    private static void showDirDialog(final Activity activity, final File dir) {
        if (dir == null || !dir.exists()) {
            Toast.makeText(activity, "Dir not found: " + (dir != null ? dir.getAbsolutePath() : "null"), Toast.LENGTH_SHORT).show();
            return;
        }
        File[] rawList = dir.listFiles();
        if (rawList == null) {
            String detail = "Cannot open/list dir (r=" + dir.canRead() + ", w=" + dir.canWrite() + "): " + dir.getAbsolutePath();
            Toast.makeText(activity, detail, Toast.LENGTH_LONG).show();
            return;
        }

        final List<File> entries = new ArrayList<>();
        Collections.addAll(entries, rawList);
        Collections.sort(entries, (a, b) -> {
            if (a.isDirectory() != b.isDirectory()) {
                return a.isDirectory() ? -1 : 1;
            }
            return a.getName().compareToIgnoreCase(b.getName());
        });

        final List<String> names = new ArrayList<>();
        File parent = dir.getParentFile();
        if (parent != null) {
            names.add(".. [Parent]");
        }
        for (File f : entries) {
            String flag = f.isDirectory()
                    ? "[DIR " + (f.canRead() ? "r" : "-") + (f.canWrite() ? "w" : "-") + "]"
                    : "[" + f.length() + "B " + (f.canWrite() ? "w" : "ro") + "]";
            names.add(f.getName() + "  " + flag);
        }

        new AlertDialog.Builder(activity)
                .setTitle(dir.getName() + " (" + entries.size() + ")")
                .setItems(names.toArray(new String[0]), (dialog, which) -> {
                    int offset = (parent != null) ? 1 : 0;
                    if (parent != null && which == 0) {
                        showDirDialog(activity, parent);
                        return;
                    }
                    File picked = entries.get(which - offset);
                    if (picked.isDirectory()) {
                        showDirDialog(activity, picked);
                    } else {
                        showFileDialog(activity, picked);
                    }
                })
                .setNegativeButton("Back", null)
                .show();
    }

    private static void showFileDialog(final Activity activity, final File file) {
        final String preview = readPreview(file, 4096);

        TextView tv = new TextView(activity);
        tv.setText(preview);
        tv.setTextSize(11f);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setPadding(24, 16, 24, 16);

        ScrollView scroll = new ScrollView(activity);
        scroll.addView(tv);

        new AlertDialog.Builder(activity)
                .setTitle(file.getName() + " (" + file.length() + "B, w=" + file.canWrite() + ")")
                .setView(scroll)
                .setPositiveButton("Edit", (d, w) -> showEditFileDialog(activity, file))
                .setNeutralButton("Replace", (d, w) -> showReplaceFromBbShareDialog(activity, file))
                .setNegativeButton("Share", (d, w) -> {
                    String res = copyFileToMainShare(activity, file, null);
                    Toast.makeText(activity, res, Toast.LENGTH_LONG).show();
                })
                .show();
    }

    private static void showEditFileDialog(final Activity activity, final File file) {
        String currentContent = readPreview(file, 32768);

        final EditText editor = new EditText(activity);
        editor.setText(currentContent);
        editor.setTextSize(11f);
        editor.setTypeface(Typeface.MONOSPACE);
        editor.setGravity(Gravity.TOP | Gravity.START);
        editor.setPadding(20, 16, 20, 16);

        ScrollView scroll = new ScrollView(activity);
        scroll.addView(editor);

        new AlertDialog.Builder(activity)
                .setTitle("Edit: " + file.getName() + " (w=" + file.canWrite() + ")")
                .setView(scroll)
                .setPositiveButton("Save", (d, w) -> {
                    try {
                        if (!file.canWrite()) {
                            Toast.makeText(activity, "ERR: Target file not writable", Toast.LENGTH_LONG).show();
                            return;
                        }
                        String updated = editor.getText().toString();
                        try (OutputStream out = new FileOutputStream(file, false)) {
                            out.write(updated.getBytes(StandardCharsets.UTF_8));
                            out.flush();
                        }
                        Toast.makeText(activity, "SAVED: " + file.length() + "B", Toast.LENGTH_SHORT).show();
                    } catch (Exception e) {
                        Toast.makeText(activity, "ERR: " + e.getClass().getSimpleName() + ": " + e.getMessage(), Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private static void showReplaceFromBbShareDialog(final Activity activity, final File targetFile) {
        File shareDir = getMainDeviceShareDir();
        File[] files = shareDir.exists() ? shareDir.listFiles() : null;
        final List<File> candidates = new ArrayList<>();
        final List<String> labels = new ArrayList<>();

        if (files != null) {
            for (File f : files) {
                if (f != null && f.isFile()) {
                    candidates.add(f);
                    labels.add(f.getName() + " (" + f.length() + "B)");
                }
            }
        }

        if (candidates.isEmpty()) {
            Toast.makeText(activity, "No files in Download/" + SHARE_FOLDER_NAME, Toast.LENGTH_LONG).show();
            return;
        }

        new AlertDialog.Builder(activity)
                .setTitle("Replace " + targetFile.getName() + " with:")
                .setItems(labels.toArray(new String[0]), (d, which) -> {
                    File chosen = candidates.get(which);
                    String res = replaceFileFromMainShare(activity, targetFile, chosen);
                    Toast.makeText(activity, res, Toast.LENGTH_LONG).show();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private static String readPreview(File file, int maxBytes) {
        try (InputStream in = new FileInputStream(file)) {
            byte[] buf = new byte[Math.min(maxBytes, (int) Math.max(1, Math.min(file.length(), maxBytes)))];
            int read = in.read(buf);
            if (read <= 0) {
                return "<empty>";
            }
            String text = new String(buf, 0, read, StandardCharsets.UTF_8);
            if (file.length() > read) {
                text += "\n\n... [truncated, total=" + file.length() + "B]";
            }
            return text;
        } catch (Exception e) {
            return "ERR reading file: " + e.getMessage();
        }
    }
}