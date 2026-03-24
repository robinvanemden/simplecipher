package com.example.simplecipher;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;

/**
 * Abstraction for QR code operations.  The 'full' flavor provides a real
 * implementation (ZXing); the 'minimal' flavor provides a no-op stub.
 * This lets MainActivity compile identically for both flavors.
 */
interface QrHelper {
    /** Generate a QR code bitmap for the given text.  Returns null on error or if unsupported. */
    Bitmap generateBitmap(String content, int size);

    /** Launch the QR barcode scanner activity.  No-op if unsupported. */
    void launchScanner(Activity activity);

    /** Parse a scan result from onActivityResult.  Returns the decoded string, or null. */
    String parseScanResult(int requestCode, int resultCode, Intent data);

    /** Whether this helper supports QR scanning (true for full, false for minimal). */
    boolean hasScanner();
}
