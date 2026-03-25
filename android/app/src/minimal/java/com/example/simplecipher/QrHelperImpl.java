package com.example.simplecipher;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;

/**
 * Minimal flavor: no QR support. No ZXing dependency, no CAMERA permission. Fingerprint
 * verification uses manual text input only.
 */
class QrHelperImpl implements QrHelper {

  @Override
  public Bitmap generateBitmap(String content, int size) {
    return null;
  }

  @Override
  public void launchScanner(Activity activity) {
    /* No-op: minimal flavor has no scanner */
  }

  @Override
  public String parseScanResult(int requestCode, int resultCode, Intent data) {
    return null;
  }

  @Override
  public boolean hasScanner() {
    return false;
  }
}
