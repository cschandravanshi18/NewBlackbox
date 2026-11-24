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
        Boolean already = ATTACHED.get(activity);
        if (already != null && already) {
            return;
        }

        new Handler(Looper.getMainLooper()).post(new Runnable() {
            @Override
            public void run() {
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
                    filesBtn.setTextSize(11f);
                    filesBtn.setTextColor(Color.WHITE);
                    filesBtn.setAllCaps(false);

                    GradientDrawable bg = new GradientDrawable();
                    bg.setColor(Color.parseColor("#CC0F172A"));
                    bg.setCornerRadius(36f);
                    filesBtn.setBackground(bg);
                    filesBtn.setPadding(24, 8, 24, 8);

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
                    lp.gravity = Gravity.TOP | Gravity.START;
                    lp.topMargin = 110;
                    lp.leftMargin = 20;

                    rootDecor.addView(filesBtn, lp);
                } catch (Throwable ignored) {
                }
            }
        });
    }

    private static void showDirDialog(final Activity activity, final File dir) {
        LinearLayout container = new LinearLayout(activity);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(28, 20, 28, 12);

        TextView info = new TextView(activity);
        info.setText("Path: " + dir.getAbsolutePath() + "\nr=" + dir.canRead() + " w=" + dir.canWrite());
        info.setTextSize(11f);
        info.setTypeface(Typeface.MONOSPACE);
        info.setTextColor(Color.DKGRAY);
        info.setPadding(0, 0, 0, 12);
        container.addView(info);

        LinearLayout navRow = new LinearLayout(activity);
        navRow.setOrientation(LinearLayout.HORIZONTAL);
        navRow.setPadding(0, 0, 0, 12);

        Button upBtn = new Button(activity);
        upBtn.setText("Up");
        upBtn.setTextSize(11f);
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
        appFilesBtn.setAllCaps(false);
        appFilesBtn.setOnClickListener(v -> showDirDialog(activity, activity.getFilesDir()));
        navRow.addView(appFilesBtn);

        Button shareBtn = new Button(activity);
        shareBtn.setText("BBShare");
        shareBtn.setTextSize(11f);
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
        listView.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_list_item_1, labels));
        listView.setOnItemClickListener((parent, view, position, id) -> {
            File clicked = entries.get(position);
            if (clicked.isDirectory()) {
                showDirDialog(activity, clicked);
            } else {
                showFileDialog(activity, clicked);
            }
        });
        container.addView(listView);

        new AlertDialog.Builder(activity)
                .setTitle("Explorer")
                .setView(container)
                .setNegativeButton("Close", null)
                .show();
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

        TextView tv = new TextView(activity);
        tv.setText(preview);
        tv.setTextSize(11f);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        tv.setPadding(28, 20, 28, 20);

        ScrollView scroll = new ScrollView(activity);
        scroll.addView(tv);

        new AlertDialog.Builder(activity)
                .setTitle(file.getName())
                .setView(scroll)
                .setPositiveButton("Copy to BBShare", (d, w) -> {
                    String res = copyFileToMainShare(activity, file, null);
                    Toast.makeText(activity, res, Toast.LENGTH_LONG).show();
                })
                .setNegativeButton("Back", null)
                .show();
    }
}