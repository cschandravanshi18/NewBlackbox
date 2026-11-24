package top.niunaijun.blackbox.fake.delegate;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.media.MediaScannerConnection;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
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
    private static final int TRANS_WHITE_BG = 0xE6FFFFFF;
    private static final int PURE_BLACK_TEXT = 0xFF000000;
    private static final WeakHashMap<Activity, Boolean> ATTACHED = new WeakHashMap<>();

    private BlackBoxShareAndExplorer() {
    }

    public static File getMainDeviceShareDir() {
        File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        return new File(downloads, SHARE_FOLDER_NAME);
    }

    public static String formatAsPrettyJson(String rawData, String prefix) {
        String trimmed = rawData == null ? "" : rawData.trim();
        try {
            if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
                return new JSONObject(trimmed).toString(2);
            }
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                return new JSONArray(trimmed).toString(2);
            }
        } catch (Exception ignored) {
        }
        try {
            JSONObject obj = new JSONObject();
            obj.put("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).format(new Date()));
            obj.put("source", (prefix == null || prefix.trim().isEmpty()) ? "diagnostic" : prefix.trim());
            obj.put("raw", rawData == null ? "" : rawData);
            return obj.toString(2);
        } catch (Exception e) {
            return "{\"raw\":\"" + (rawData == null ? "" : rawData.replace("\"", "\\\"")) + "\"}";
        }
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

    public static String saveJsonDiagnosticToMainShare(Context context, String rawData, String prefix) {
        try {
            String formattedJson = formatAsPrettyJson(rawData, prefix);
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

    /**
     * "Send Diagnostic" बटन या एक्शन से कॉल करें:
     * 1) JSON फ़ाइल को Download/BlackBoxShare में सेव करता है
     * 2) क्लिपबोर्ड में कॉपी करता है
     * 3) तुरंत डायलॉग खोलकर विवरण दिखाता है (ताकि कुछ न कुछ हमेशा खुले)
     * 4) सिस्टम शेयर इंटेंट भी शुरू करने की कोशिश करता है
     */
    public static void handleSendDiagnosticAction(final Activity activity, final String rawDiagData, final String prefix) {
        if (activity == null || activity.isFinishing() || activity.isDestroyed()) {
            return;
        }
        final String prettyJson = formatAsPrettyJson(rawDiagData, prefix);
        final String saveResult = saveJsonDiagnosticToMainShare(activity, prettyJson, prefix);

        try {
            ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("DiagnosticJSON", prettyJson));
            }
        } catch (Throwable ignored) {
        }

        // तुरंत इन-ऐप डायलॉग खोलें ताकि उपयोगकर्ता को साफ़ दिखे कि क्या सेव हुआ
        new Handler(Looper.getMainLooper()).post(() -> {
            if (activity.isFinishing() || activity.isDestroyed()) return;
            LinearLayout box = new LinearLayout(activity);
            box.setOrientation(LinearLayout.VERTICAL);
            box.setBackgroundColor(TRANS_WHITE_BG);
            box.setPadding(24, 20, 24, 16);

            TextView statusTv = new TextView(activity);
            statusTv.setText(saveResult + "\n(JSON copied to clipboard)");
            statusTv.setTextColor(PURE_BLACK_TEXT);
            statusTv.setTextSize(12f);
            statusTv.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            statusTv.setPadding(0, 0, 0, 12);
            box.addView(statusTv);

            TextView bodyTv = new TextView(activity);
            bodyTv.setText(prettyJson.length() > 4000 ? prettyJson.substring(0, 4000) + "\n...(truncated)" : prettyJson);
            bodyTv.setTextColor(PURE_BLACK_TEXT);
            bodyTv.setTextSize(11f);
            bodyTv.setTypeface(Typeface.MONOSPACE);
            bodyTv.setTextIsSelectable(true);

            ScrollView sv = new ScrollView(activity);
            sv.addView(bodyTv);
            box.addView(sv);

            AlertDialog dialog = new AlertDialog.Builder(activity)
                    .setTitle("Diagnostic JSON")
                    .setView(box)
                    .setPositiveButton("Open Share Sheet", (d, w) -> {
                        try {
                            Intent send = new Intent(Intent.ACTION_SEND);
                            send.setType("application/json");
                            send.putExtra(Intent.EXTRA_SUBJECT, "Diagnostic JSON");
                            send.putExtra(Intent.EXTRA_TEXT, prettyJson);
                            Intent chooser = Intent.createChooser(send, "Share Diagnostic JSON");
                            activity.startActivity(chooser);
                        } catch (Throwable t) {
                            Toast.makeText(activity, "Share sheet blocked/unavailable: saved to Download/BlackBoxShare", Toast.LENGTH_LONG).show();
                        }
                    })
                    .setNegativeButton("Close", null)
                    .create();
            dialog.show();
            if (dialog.getWindow() != null) {
                dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
            }
        });
    }

    public static void attachDefaultExplorer(final Activity activity) {
        if (activity == null || activity.isFinishing() || activity.isDestroyed()) {
            return;
        }
        Boolean already = ATTACHED.get(activity);
        if (already != null && already) {
            return;
        }

        new Handler(Looper.getMainLooper()).post(() -> {
            try {
                if (activity.isFinishing() || activity.isDestroyed()) {
                    return;
                }
                if (Boolean.TRUE.equals(ATTACHED.get(activity))) {
                    return;
                }
                if (!(activity.getWindow().getDecorView() instanceof ViewGroup)) {
                    return;
                }
                ViewGroup rootDecor = (ViewGroup) activity.getWindow().getDecorView();
                ATTACHED.put(activity, Boolean.TRUE);

                Button filesBtn = new Button(activity);
                filesBtn.setText("Files");
                filesBtn.setTextSize(12f);
                filesBtn.setTypeface(Typeface.DEFAULT_BOLD);
                filesBtn.setTextColor(PURE_BLACK_TEXT);
                filesBtn.setAllCaps(false);

                GradientDrawable bg = new GradientDrawable();
                bg.setColor(TRANS_WHITE_BG);
                bg.setStroke(2, Color.parseColor("#33000000"));
                bg.setCornerRadius(36f);
                filesBtn.setBackground(bg);
                filesBtn.setPadding(28, 8, 28, 8);

                filesBtn.setOnClickListener(v -> {
                    File startDir = activity.getFilesDir().getParentFile();
                    if (startDir == null) {
                        startDir = activity.getFilesDir();
                    }
                    showDirDialog(activity, startDir);
                });

                FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                );
                // टॉप-सेंटर पोजीशन
                lp.gravity = Gravity.TOP | Gravity.CENTER_HORIZONTAL;
                lp.topMargin = 100;

                rootDecor.addView(filesBtn, lp);
            } catch (Throwable ignored) {
            }
        });
    }

    private static void showDirDialog(final Activity activity, final File dir) {
        LinearLayout container = new LinearLayout(activity);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setBackgroundColor(TRANS_WHITE_BG);
        container.setPadding(24, 18, 24, 12);

        TextView info = new TextView(activity);
        info.setText("Path: " + dir.getAbsolutePath() + "\nr=" + dir.canRead() + " w=" + dir.canWrite());
        info.setTextSize(11f);
        info.setTypeface(Typeface.MONOSPACE);
        info.setTextColor(PURE_BLACK_TEXT);
        info.setPadding(0, 0, 0, 10);
        container.addView(info);

        LinearLayout navRow = new LinearLayout(activity);
        navRow.setOrientation(LinearLayout.HORIZONTAL);
        navRow.setPadding(0, 0, 0, 10);

        Button upBtn = new Button(activity);
        upBtn.setText("Up");
        upBtn.setTextSize(11f);
        upBtn.setTextColor(PURE_BLACK_TEXT);
        upBtn.setAllCaps(false);
        upBtn.setOnClickListener(v -> {
            if (dir.getParentFile() != null) {
                showDirDialog(activity, dir.getParentFile());
            }
        });
        navRow.addView(upBtn);

        Button appFilesBtn = new Button(activity);
        appFilesBtn.setText("AppFiles");
        appFilesBtn.setTextSize(11f);
        appFilesBtn.setTextColor(PURE_BLACK_TEXT);
        appFilesBtn.setAllCaps(false);
        appFilesBtn.setOnClickListener(v -> showDirDialog(activity, activity.getFilesDir()));
        navRow.addView(appFilesBtn);

        Button shareBtn = new Button(activity);
        shareBtn.setText("BBShare");
        shareBtn.setTextSize(11f);
        shareBtn.setTextColor(PURE_BLACK_TEXT);
        shareBtn.setAllCaps(false);
        shareBtn.setOnClickListener(v -> {
            File sDir = getMainDeviceShareDir();
            if (!sDir.exists()) {
                sDir.mkdirs();
            }
            showDirDialog(activity, sDir);
        });
        navRow.addView(shareBtn);

        container.addView(navRow);

        File[] rawList = dir.listFiles();
        final List<File> entries = new ArrayList<>();
        if (rawList != null) {
            Collections.addAll(entries, rawList);
            Collections.sort(entries, new Comparator<File>() {
                @Override
                public int compare(File a, File b) {
                    if (a.isDirectory() != b.isDirectory()) {
                        return a.isDirectory() ? -1 : 1;
                    }
                    return a.getName().toLowerCase(Locale.ROOT).compareTo(b.getName().toLowerCase(Locale.ROOT));
                }
            });
        }

        List<String> labels = new ArrayList<>();
        for (File f : entries) {
            String tag = f.isDirectory() ? "[DIR]" : "[FILE]";
            labels.add(tag + " " + f.getName() + " (" + f.length() + "B, r:" + (f.canRead() ? 1 : 0) + ")");
        }

        ListView listView = new ListView(activity);
        listView.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 650));
        listView.setBackgroundColor(Color.TRANSPARENT);
        listView.setAdapter(new ArrayAdapter<String>(activity, android.R.layout.simple_list_item_1, labels) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View view = super.getView(position, convertView, parent);
                if (view instanceof TextView) {
                    TextView tv = (TextView) view;
                    tv.setTextColor(PURE_BLACK_TEXT);
                    tv.setBackgroundColor(Color.TRANSPARENT);
                    tv.setTextSize(12f);
                }
                return view;
            }
        });
        listView.setOnItemClickListener((parent, view, position, id) -> {
            File clicked = entries.get(position);
            if (clicked.isDirectory()) {
                showDirDialog(activity, clicked);
            } else {
                showFileDialog(activity, clicked);
            }
        });
        container.addView(listView);

        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle("Explorer")
                .setView(container)
                .setNegativeButton("Close", null)
                .create();
        dialog.show();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
    }

    private static void showFileDialog(final Activity activity, final File file) {
        String preview;
        try {
            if (file.canRead()) {
                byte[] bytes = new byte[(int) Math.min(file.length(), 3000L)];
                try (InputStream in = new FileInputStream(file)) {
                    int read = in.read(bytes);
                    preview = read > 0 ? new String(bytes, 0, read, StandardCharsets.UTF_8) : "(Empty file)";
                }
                if (file.length() > 3000L) {
                    preview = preview + "\n\n...(truncated)";
                }
            } else {
                preview = "Not readable (canRead=false)";
            }
        } catch (Exception e) {
            preview = "Read error: " + e.getMessage();
        }

        LinearLayout wrap = new LinearLayout(activity);
        wrap.setOrientation(LinearLayout.VERTICAL);
        wrap.setBackgroundColor(TRANS_WHITE_BG);
        wrap.setPadding(24, 18, 24, 16);

        TextView tv = new TextView(activity);
        tv.setText(preview);
        tv.setTextSize(11f);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextColor(PURE_BLACK_TEXT);
        tv.setTextIsSelectable(true);

        ScrollView scroll = new ScrollView(activity);
        scroll.addView(tv);
        wrap.addView(scroll);

        AlertDialog dialog = new AlertDialog.Builder(activity)
                .setTitle(file.getName())
                .setView(wrap)
                .setPositiveButton("Copy to BBShare", (d, w) -> {
                    String res = copyFileToMainShare(activity, file, null);
                    Toast.makeText(activity, res, Toast.LENGTH_LONG).show();
                })
                .setNegativeButton("Back", null)
                .create();
        dialog.show();
        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }
    }
}